// SPDX-License-Identifier: GPL-2.0-only OR Linux-OpenIB

/*
 * Mellanox Public Key Accelerator (MLXBF_PKA) driver
 *
 * Copyright (c) 2020 NVIDIA Corporation. All rights reserved.
 */

#include <linux/acpi.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/hw_random.h>
#include <linux/interrupt.h>
#include <linux/iommu.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of_device.h>
#include <linux/of_irq.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/vfio.h>

#include "mlxbf_pka_dev.h"

#define MLXBF_PKA_DRIVER_VERSION "v2.0"
#define MLXBF_PKA_DRIVER_NAME "pka-mlxbf"

#define MLXBF_PKA_DRIVER_DESCRIPTION "BlueField PKA driver"

#define MLXBF_PKA_DEVICE_COMPAT "mlx,mlxbf-pka"
#define MLXBF_PKA_RING_DEVICE_COMPAT "mlx,mlxbf-pka-ring"

#define MLXBF_PKA_DEVICE_ACPIHID "MLNXBF10"
#define MLXBF_PKA_RING_DEVICE_ACPIHID "MLNXBF11"

static DEFINE_MUTEX(mlxbf_pka_drv_lock);

static u32 mlxbf_pka_device_cnt;
static u32 mlxbf_pka_ring_device_cnt;

static const char mlxbf_pka_compat[] = MLXBF_PKA_DEVICE_COMPAT;
static const char mlxbf_pka_ring_compat[] = MLXBF_PKA_RING_DEVICE_COMPAT;

static const char mlxbf_pka_acpihid[] = MLXBF_PKA_DEVICE_ACPIHID;
static const char mlxbf_pka_ring_acpihid[] = MLXBF_PKA_RING_DEVICE_ACPIHID;

struct mlxbf_pka_info {
	struct device *dev;
	const char *name;
	const char *version;
	const char *compat;
	const char *acpihid;
	u8 flag;
	struct module *module;
	void *priv;
};

/* defines for mlxbf_pka_info->flags */
#define MLXBF_PKA_DRIVER_FLAG_RING_DEVICE 1
#define MLXBF_PKA_DRIVER_FLAG_DEVICE 2

enum {  MLXBF_PKA_REVISION_1 = 1,
	MLXBF_PKA_REVISION_2,
};

struct mlxbf_pka_platdata {
	struct platform_device *pdev;
	struct mlxbf_pka_info *info;
	spinlock_t lock;
	unsigned long irq_flags;
};

/* Bits in mlxbf_pka_platdata.irq_flags */
enum { MLXBF_PKA_IRQ_DISABLED = 0,
};

struct mlxbf_pka_ring_region {
	u64 off;
	u64 addr;
	resource_size_t size;
	u32 flags;
	u32 type;
	void __iomem *ioaddr;
};

/* defines for pka_ring_region->flags */
#define MLXBF_PKA_RING_REGION_FLAG_READ BIT(0) /* Region supports read */
#define MLXBF_PKA_RING_REGION_FLAG_WRITE BIT(1) /* Region supports write */
#define MLXBF_PKA_RING_REGION_FLAG_MMAP BIT(2) /* Region supports mmap */

/* defines for mlxbf_pka_ring_region->type */
#define MLXBF_PKA_RING_RES_TYPE_NONE 0
#define MLXBF_PKA_RING_RES_TYPE_WORDS BIT(0) /* info control/status words */
#define MLXBF_PKA_RING_RES_TYPE_CNTRS BIT(1) /* count registers */
#define MLXBF_PKA_RING_RES_TYPE_MEM BIT(2) /* window RAM region */

#define MLXBF_PKA_DRIVER_RING_DEV_MAX MLXBF_PKA_MAX_NUM_RINGS

struct mlxbf_pka_ring_device {
	struct mlxbf_pka_info *info;
	struct device *device;
	struct iommu_group *group;
	s32 group_id;
	u32 device_id;
	u32 parent_device_id;
	struct mutex mutex;
	u32 flags;
	struct module *parent_module;
	struct mlxbf_pka_dev_ring_t *ring;
	int minor;
	u32 num_regions;
	struct mlxbf_pka_ring_region *regions;
};

#define MLXBF_PKA_DRIVER_DEV_MAX MLXBF_PKA_MAX_NUM_IO_BLOCKS
#define MLXBF_PKA_DRIVER_RING_NUM_REGIONS_MAX MLXBF_PKA_MAX_NUM_RING_RESOURCES

/* defines for region index */
enum {	MLXBF_PKA_RING_REGION_WORDS_IDX = 0,
	MLXBF_PKA_RING_REGION_CNTRS_IDX,
	MLXBF_PKA_RING_REGION_MEM_IDX,
};

#define MLXBF_PKA_RING_REGION_OFFSET_SHIFT 40
#define MLXBF_PKA_RING_REGION_OFFSET_MASK                                      \
	(((u64)(1) << MLXBF_PKA_RING_REGION_OFFSET_SHIFT) - 1)

#define MLXBF_PKA_RING_OFFSET_TO_INDEX(off)                                    \
	((off) >> MLXBF_PKA_RING_REGION_OFFSET_SHIFT)

#define MLXBF_PKA_RING_REGION_INDEX_TO_OFFSET(index)                           \
	((u64)(index) << MLXBF_PKA_RING_REGION_OFFSET_SHIFT)

struct mlxbf_pka_device {
	struct mlxbf_pka_info *info;
	struct device *device;
	u32 device_id;
	u8 fw_id;
	struct mutex mutex;
	struct resource *resource;
	struct mlxbf_pka_dev_shim_t *shim;
	long irq;
	struct hwrng rng;
};

/* defines for mlxbf_pka_device->irq */
#define MLXBF_PKA_IRQ_CUSTOM -1
#define MLXBF_PKA_IRQ_NONE 0

/* Hardware interrupt handler */
static irqreturn_t mlxbf_pka_drv_irq_handler(int irq, void *device)
{
	struct mlxbf_pka_device *mlxbf_pka_dev =
		(struct mlxbf_pka_device *)device;
	struct platform_device *pdev =
		to_platform_device(mlxbf_pka_dev->device);
	struct mlxbf_pka_platdata *priv = platform_get_drvdata(pdev);

	MLXBF_PKA_DEBUG(MLXBF_PKA_DRIVER, "handle irq in device %u\n",
			mlxbf_pka_dev->device_id);

	/* Just disable the interrupt in the interrupt controller */

	spin_lock(&priv->lock);
	if (!__test_and_set_bit(MLXBF_PKA_IRQ_DISABLED, &priv->irq_flags))
		disable_irq_nosync(irq);
	spin_unlock(&priv->lock);

	return IRQ_HANDLED;
}

static int mlxbf_pka_drv_register_irq(struct mlxbf_pka_device *mlxbf_pka_dev)
{
	if (mlxbf_pka_dev->irq &&
	    mlxbf_pka_dev->irq != MLXBF_PKA_IRQ_CUSTOM) {
		/*
		 * Allow sharing the irq among several devices (child devices
		 * so far)
		 */
		return request_irq(mlxbf_pka_dev->irq,
				   (irq_handler_t)mlxbf_pka_drv_irq_handler,
				   IRQF_SHARED, mlxbf_pka_dev->info->name,
				   mlxbf_pka_dev);
	}

	return -ENXIO;
}

static int
mlxbf_pka_drv_ring_regions_init(struct mlxbf_pka_ring_device *ring_dev)
{
	struct mlxbf_pka_ring_region *region;
	struct mlxbf_pka_dev_ring_t *ring;
	struct mlxbf_pka_dev_res_t *res;
	u32 num_regions;
	u64 shim_base;

	ring = ring_dev->ring;
	if (!ring || !ring->shim)
		return -ENXIO;

	num_regions = ring->resources_num;
	ring_dev->num_regions = num_regions;
	ring_dev->regions = kcalloc(
		num_regions, sizeof(struct mlxbf_pka_ring_region), GFP_KERNEL);
	if (!ring_dev->regions)
		return -ENOMEM;

	shim_base = ring->shim->base;

	/* Information words region */
	res = &ring->resources.info_words;
	region = &ring_dev->regions[MLXBF_PKA_RING_REGION_WORDS_IDX];
	/* map offset to the physical address */
	region->off =
		MLXBF_PKA_RING_REGION_INDEX_TO_OFFSET(MLXBF_PKA_RING_REGION_WORDS_IDX);
	region->addr = res->base + shim_base;
	region->size = res->size;
	region->type = MLXBF_PKA_RING_RES_TYPE_WORDS;
	region->flags |=
		(MLXBF_PKA_RING_REGION_FLAG_MMAP |
		 MLXBF_PKA_RING_REGION_FLAG_READ |
		 MLXBF_PKA_RING_REGION_FLAG_WRITE);

	/* Count registers region */
	res = &ring->resources.counters;
	region = &ring_dev->regions[MLXBF_PKA_RING_REGION_CNTRS_IDX];
	/* map offset to the physical address */
	region->off =
		MLXBF_PKA_RING_REGION_INDEX_TO_OFFSET(MLXBF_PKA_RING_REGION_CNTRS_IDX);
	region->addr = res->base + shim_base;
	region->size = res->size;
	region->type = MLXBF_PKA_RING_RES_TYPE_CNTRS;
	region->flags |=
		(MLXBF_PKA_RING_REGION_FLAG_MMAP |
		 MLXBF_PKA_RING_REGION_FLAG_READ |
		 MLXBF_PKA_RING_REGION_FLAG_WRITE);

	/* Window ram region */
	res = &ring->resources.window_ram;
	region = &ring_dev->regions[MLXBF_PKA_RING_REGION_MEM_IDX];
	/* map offset to the physical address */
	region->off =
		MLXBF_PKA_RING_REGION_INDEX_TO_OFFSET(MLXBF_PKA_RING_REGION_MEM_IDX);
	region->addr = res->base + shim_base;
	region->size = res->size;
	region->type = MLXBF_PKA_RING_RES_TYPE_MEM;
	region->flags |=
		(MLXBF_PKA_RING_REGION_FLAG_MMAP |
		 MLXBF_PKA_RING_REGION_FLAG_READ |
		 MLXBF_PKA_RING_REGION_FLAG_WRITE);

	return 0;
}

static void
mlxbf_pka_drv_ring_regions_cleanup(struct mlxbf_pka_ring_device *ring_dev)
{
	/* clear ring device regions */
	ring_dev->num_regions = 0;
	kfree(ring_dev->regions);
}

static int mlxbf_pka_drv_ring_open(void *device_data)
{
	struct mlxbf_pka_ring_device *ring_dev = device_data;
	struct mlxbf_pka_info *info = ring_dev->info;
	struct mlxbf_pka_ring_info_t ring_info;
	int error;

	MLXBF_PKA_DEBUG(MLXBF_PKA_DRIVER,
			"open ring device %u (device_data:%p)\n",
			ring_dev->device_id, ring_dev);

	if (!try_module_get(info->module))
		return -ENODEV;

	/* Initialize regions */
	error = mlxbf_pka_drv_ring_regions_init(ring_dev);
	if (error) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DRIVER,
				"failed to initialize regions\n");
		module_put(info->module);
		return error;
	}

	ring_info.ring_id = ring_dev->device_id;
	error = mlxbf_pka_dev_open_ring(&ring_info);
	if (error) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DRIVER, "failed to open ring %u\n",
				ring_dev->device_id);
		mlxbf_pka_drv_ring_regions_cleanup(ring_dev);
		module_put(info->module);
		return error;
	}

	return 0;
}

static void mlxbf_pka_drv_ring_release(void *device_data)
{
	struct mlxbf_pka_ring_device *ring_dev = device_data;
	struct mlxbf_pka_info *info = ring_dev->info;
	struct mlxbf_pka_ring_info_t ring_info;
	int error;

	MLXBF_PKA_DEBUG(MLXBF_PKA_DRIVER,
			"release ring device %u (device_data:%p)\n",
			ring_dev->device_id, ring_dev);

	ring_info.ring_id = ring_dev->device_id;
	error = mlxbf_pka_dev_close_ring(&ring_info);
	if (error)
		MLXBF_PKA_ERROR(MLXBF_PKA_DRIVER, "failed to close ring %u\n",
				ring_dev->device_id);

	mlxbf_pka_drv_ring_regions_cleanup(ring_dev);
	module_put(info->module);
}

static int mlxbf_pka_drv_ring_mmap_region(struct mlxbf_pka_ring_region region,
					  struct vm_area_struct *vma)
{
	u64 req_len, pgoff, req_start;

	req_len = vma->vm_end - vma->vm_start;
	pgoff = vma->vm_pgoff &
		((1U << (MLXBF_PKA_RING_REGION_OFFSET_SHIFT - PAGE_SHIFT)) - 1);
	req_start = pgoff << PAGE_SHIFT;

	region.size = roundup(region.size, PAGE_SIZE);

	if (req_start + req_len > region.size)
		return -EINVAL;

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	vma->vm_pgoff = (region.addr >> PAGE_SHIFT) + pgoff;

	return remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff, req_len,
			       vma->vm_page_prot);
}

static int mlxbf_pka_drv_ring_mmap(void *device_data,
				   struct vm_area_struct *vma)
{
	struct mlxbf_pka_ring_device *ring_dev = device_data;
	struct mlxbf_pka_ring_region *region;
	unsigned int index;

	MLXBF_PKA_DEBUG(MLXBF_PKA_DRIVER, "mmap device %u\n",
			ring_dev->device_id);

	index = vma->vm_pgoff >>
		(MLXBF_PKA_RING_REGION_OFFSET_SHIFT - PAGE_SHIFT);

	if (vma->vm_end < vma->vm_start)
		return -EINVAL;
	if (!(vma->vm_flags & VM_SHARED))
		return -EINVAL;
	if (index >= ring_dev->num_regions)
		return -EINVAL;
	if (vma->vm_start & ~PAGE_MASK)
		return -EINVAL;
	if (vma->vm_end & ~PAGE_MASK)
		return -EINVAL;

	region = &ring_dev->regions[index];

	if (!(region->flags & MLXBF_PKA_RING_REGION_FLAG_MMAP))
		return -EINVAL;

	if (!(region->flags & MLXBF_PKA_RING_REGION_FLAG_READ) &&
	    (vma->vm_flags & VM_READ))
		return -EINVAL;

	if (!(region->flags & MLXBF_PKA_RING_REGION_FLAG_WRITE) &&
	    (vma->vm_flags & VM_WRITE))
		return -EINVAL;

	vma->vm_private_data = ring_dev;

	if (region->type & MLXBF_PKA_RING_RES_TYPE_CNTRS ||
	    region->type & MLXBF_PKA_RING_RES_TYPE_MEM)
		return mlxbf_pka_drv_ring_mmap_region(ring_dev->regions[index],
						      vma);

	if (region->type & MLXBF_PKA_RING_RES_TYPE_WORDS)
		/*
		 * Currently user space is not allowed to access this
		 * region.
		 */
		return -EINVAL;

	return -EINVAL;
}

static long mlxbf_pka_drv_ring_ioctl(void *device_data, unsigned int cmd,
				 unsigned long arg)
{
	struct mlxbf_pka_ring_device *ring_dev = device_data;
	int error = -ENOTTY;

	if (cmd == MLXBF_PKA_RING_GET_REGION_INFO) {
		struct mlxbf_pka_dev_region_info_t info;

		info.mem_index = MLXBF_PKA_RING_REGION_MEM_IDX;
		info.mem_offset = ring_dev->regions[info.mem_index].off;
		info.mem_size = ring_dev->regions[info.mem_index].size;

		info.reg_index = MLXBF_PKA_RING_REGION_CNTRS_IDX;
		info.reg_offset = ring_dev->regions[info.reg_index].off;
		info.reg_size = ring_dev->regions[info.reg_index].size;

		return copy_to_user((void __user *)arg, &info, sizeof(info)) ?
			       -EFAULT :
			       0;

	} else if (cmd == MLXBF_PKA_GET_RING_INFO) {
		struct mlxbf_pka_dev_hw_ring_info_t *this_ring_info;
		struct mlxbf_pka_dev_hw_ring_info_t hw_ring_info;

		this_ring_info = ring_dev->ring->ring_info;

		hw_ring_info.cmmd_base = this_ring_info->cmmd_base;
		hw_ring_info.rslt_base = this_ring_info->rslt_base;
		hw_ring_info.size = this_ring_info->size;
		hw_ring_info.host_desc_size = this_ring_info->host_desc_size;
		hw_ring_info.in_order = this_ring_info->in_order;
		hw_ring_info.cmmd_rd_ptr = this_ring_info->cmmd_rd_ptr;
		hw_ring_info.rslt_wr_ptr = this_ring_info->rslt_wr_ptr;
		hw_ring_info.cmmd_rd_stats = this_ring_info->cmmd_rd_ptr;
		hw_ring_info.rslt_wr_stats = this_ring_info->rslt_wr_stats;

		return copy_to_user((void __user *)arg, &hw_ring_info,
				    sizeof(hw_ring_info)) ?
			       -EFAULT :
			       0;
	} else if (cmd == MLXBF_PKA_CLEAR_RING_COUNTERS) {
		return mlxbf_pka_dev_clear_ring_counters(ring_dev->ring);
	}

	return error;
}

static struct mlxbf_pka {
	struct class *class;
	struct idr    ring_idr;
	struct mutex  ring_lock;
	struct cdev   ring_cdev;
	dev_t         ring_devt;
} pka;

static int mlxbf_pka_drv_open(struct inode *inode, struct file *filep)
{
	struct mlxbf_pka_ring_device *ring_dev;
	int ret;

	ring_dev = idr_find(&pka.ring_idr, iminor(inode));
	if (!ring_dev) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DRIVER,
			  "failed to find idr for device %d\n",
			  ring_dev->device_id);
		return -ENODEV;
	}

	ret = mlxbf_pka_drv_ring_open(ring_dev);
	if (ret)
		return ret;

	filep->private_data = ring_dev;
	return 0;
}

static int mlxbf_pka_drv_release(struct inode *inode, struct file *filep)
{
	struct mlxbf_pka_ring_device *ring_dev = filep->private_data;

	filep->private_data = NULL;
	mlxbf_pka_drv_ring_release(ring_dev);

	return 0;
}

static int mlxbf_pka_drv_mmap(struct file *filep, struct vm_area_struct *vma)
{
	return mlxbf_pka_drv_ring_mmap(filep->private_data, vma);
}

static long mlxbf_pka_drv_unlocked_ioctl(struct file *filep, unsigned int cmd,
					 unsigned long arg)
{
	return mlxbf_pka_drv_ring_ioctl(filep->private_data, cmd, arg);
}

static const struct file_operations pka_ring_fops = {
	.owner          = THIS_MODULE,
	.open           = mlxbf_pka_drv_open,
	.release        = mlxbf_pka_drv_release,
	.unlocked_ioctl = mlxbf_pka_drv_unlocked_ioctl,
	.mmap           = mlxbf_pka_drv_mmap,
};

static int mlxbf_pka_drv_add_ring_device(struct mlxbf_pka_ring_device *ring_dev)
{
	struct device *dev = ring_dev->device;

	ring_dev->minor = idr_alloc(&pka.ring_idr,
				    ring_dev, 0, MINORMASK + 1, GFP_KERNEL);
	if (ring_dev->minor < 0) {
		MLXBF_PKA_DEBUG(MLXBF_PKA_DRIVER,
			  "failed to alloc minor to device %d\n",
			  ring_dev->device_id);
		return ring_dev->minor;
	}

	dev = device_create(pka.class, NULL,
			    MKDEV(MAJOR(pka.ring_devt), ring_dev->minor),
			    ring_dev, "%d", ring_dev->device_id);
	if (IS_ERR(dev)) {
		MLXBF_PKA_DEBUG(MLXBF_PKA_DRIVER,
			  "failed to create device %d\n",
			  ring_dev->device_id);
		idr_remove(&pka.ring_idr, ring_dev->minor);
		return PTR_ERR(dev);
	}

	MLXBF_PKA_DEBUG(MLXBF_PKA_DRIVER,
		  "ring device %d minor:%d\n",
		  ring_dev->device_id, ring_dev->minor);

	return 0;
}

static struct mlxbf_pka_ring_device *
mlxbf_pka_drv_del_ring_device(struct device *dev)
{
	struct platform_device *pdev =
		container_of(dev, struct platform_device, dev);
	struct mlxbf_pka_platdata *priv = platform_get_drvdata(pdev);
	struct mlxbf_pka_info *info = priv->info;
	struct mlxbf_pka_ring_device *mlxbf_pka_ring_dev = info->priv;

	if (mlxbf_pka_ring_dev) {
		device_destroy(pka.class, MKDEV(MAJOR(pka.ring_devt),
						mlxbf_pka_ring_dev->minor));
		idr_remove(&pka.ring_idr, mlxbf_pka_ring_dev->minor);
	}

	return mlxbf_pka_ring_dev;
}

static char *mlxbf_pka_drv_devnode(struct device *dev, umode_t *mode)
{
	return kasprintf(GFP_KERNEL, "pka/%s", dev_name(dev));
}

static int mlxbf_pka_drv_init_class(void)
{
	int ret;

	idr_init(&pka.ring_idr);
	/* /sys/class/pka/$RING */
	pka.class = class_create(THIS_MODULE, "pka");
	if (IS_ERR(pka.class))
		return PTR_ERR(pka.class);

	/* /dev/pka/$RING */
	pka.class->devnode = mlxbf_pka_drv_devnode;

	ret = alloc_chrdev_region(&pka.ring_devt, 0, MINORMASK, "pka");
	if (ret)
		goto err_alloc_chrdev;

	cdev_init(&pka.ring_cdev, &pka_ring_fops);
	ret = cdev_add(&pka.ring_cdev, pka.ring_devt, MINORMASK);
	if (ret)
		goto err_cdev_add;

	return 0;

err_cdev_add:
	unregister_chrdev_region(pka.ring_devt, MINORMASK);
err_alloc_chrdev:
	class_destroy(pka.class);
	pka.class = NULL;
	return ret;
}

static void mlxbf_pka_drv_destroy_class(void)
{
	idr_destroy(&pka.ring_idr);
	cdev_del(&pka.ring_cdev);
	unregister_chrdev_region(pka.ring_devt, MINORMASK);
	class_destroy(pka.class);
	pka.class = NULL;
}

/*
 * Note that this function must be serialized because it calls
 * 'mlxbf_pka_dev_register_shim' which manipulates common counters for
 * mlxbf_pka devices.
 */
static int mlxbf_pka_drv_register_device(struct mlxbf_pka_device *mlxbf_pka_dev)
{
	u64 mlxbf_pka_shim_base;
	u64 mlxbf_pka_shim_size;
	u8 mlxbf_pka_shim_fw_id;
	u32 mlxbf_pka_shim_id;

	/* Register Shim */
	mlxbf_pka_shim_id = mlxbf_pka_dev->device_id;
	mlxbf_pka_shim_base = mlxbf_pka_dev->resource->start;
	mlxbf_pka_shim_size =
		mlxbf_pka_dev->resource->end - mlxbf_pka_shim_base;
	mlxbf_pka_shim_fw_id = mlxbf_pka_dev->fw_id;

	mlxbf_pka_dev->shim = mlxbf_pka_dev_register_shim(mlxbf_pka_shim_id,
							  mlxbf_pka_shim_base,
							  mlxbf_pka_shim_size,
							  mlxbf_pka_shim_fw_id);
	if (!mlxbf_pka_dev->shim) {
		MLXBF_PKA_DEBUG(
			MLXBF_PKA_DRIVER,
			"failed to register shim id=%u, base=0x%llx, size=0x%llx\n",
			mlxbf_pka_shim_id, mlxbf_pka_shim_base,
			mlxbf_pka_shim_size);
		return -EFAULT;
	}

	return 0;
}

static int
mlxbf_pka_drv_unregister_device(struct mlxbf_pka_device *mlxbf_pka_dev)
{
	if (!mlxbf_pka_dev)
		return -EINVAL;

	if (mlxbf_pka_dev->shim) {
		MLXBF_PKA_DEBUG(MLXBF_PKA_DRIVER, "unregister device shim %u\n",
				mlxbf_pka_dev->shim->shim_id);
		return mlxbf_pka_dev_unregister_shim(mlxbf_pka_dev->shim);
	}

	return 0;
}

/*
 * Note that this function must be serialized because it calls
 * 'mlxbf_pka_dev_register_ring' which manipulates common counters for
 * ring devices.
 */
static int mlxbf_pka_drv_register_ring_device(
	struct mlxbf_pka_ring_device *mlxbf_pka_ring_dev)
{
	u32 ring_id;
	u32 shim_id;

	ring_id = mlxbf_pka_ring_dev->device_id;
	shim_id = mlxbf_pka_ring_dev->parent_device_id;

	mlxbf_pka_ring_dev->ring =
		mlxbf_pka_dev_register_ring(ring_id, shim_id);
	if (!mlxbf_pka_ring_dev->ring) {
		MLXBF_PKA_DEBUG(MLXBF_PKA_DRIVER,
				"failed to register ring %d\n", ring_id);
		return -EFAULT;
	}

	return 0;
}

static int mlxbf_pka_drv_unregister_ring_device(
	struct mlxbf_pka_ring_device *mlxbf_pka_ring_dev)
{
	if (!mlxbf_pka_ring_dev)
		return -EINVAL;

	if (mlxbf_pka_ring_dev->ring) {
		MLXBF_PKA_DEBUG(MLXBF_PKA_DRIVER,
				"unregister ring device ring %u\n",
				mlxbf_pka_ring_dev->ring->ring_id);
		return mlxbf_pka_dev_unregister_ring(mlxbf_pka_ring_dev->ring);
	}

	return 0;
}

static const struct of_device_id mlxbf_pka_ring_match[] = {
	{ .compatible = MLXBF_PKA_RING_DEVICE_COMPAT },
	{},
};

static int mlxbf_pka_drv_rng_read(struct hwrng *rng, void *data, size_t max,
				  bool wait)
{
	struct mlxbf_pka_device *mlxbf_pka_dev =
		container_of(rng, struct mlxbf_pka_device, rng);
	u32 *buffer = data;
	int ret;

	ret = mlxbf_pka_dev_trng_read(mlxbf_pka_dev->shim, buffer, max);
	if (ret) {
		MLXBF_PKA_DEBUG(MLXBF_PKA_DRIVER,
				"%s: failed to read random bytes ret=%d",
				rng->name, ret);
		return 0;
	}

	return max;
}

static int mlxbf_pka_drv_probe_device(struct mlxbf_pka_info *info)
{
	struct device *dev = info->dev;
	struct platform_device *pdev = to_platform_device(dev);
	struct device_node *of_node = dev->of_node;
	struct mlxbf_pka_device *mlxbf_pka_dev;
	struct hwrng *trng;
	u8 revision;
	int ret;

	if (!info)
		return -EINVAL;

	mlxbf_pka_dev = kzalloc(sizeof(*mlxbf_pka_dev), GFP_KERNEL);
	if (!mlxbf_pka_dev)
		return -ENOMEM;

	mutex_lock(&mlxbf_pka_drv_lock);
	mlxbf_pka_device_cnt += 1;
	if (mlxbf_pka_device_cnt > MLXBF_PKA_DRIVER_DEV_MAX) {
		MLXBF_PKA_DEBUG(MLXBF_PKA_DRIVER, "cannot support %u devices\n",
				mlxbf_pka_device_cnt);
		kfree(mlxbf_pka_dev);
		mutex_unlock(&mlxbf_pka_drv_lock);
		return -EPERM;
	}
	mlxbf_pka_dev->device_id = mlxbf_pka_device_cnt - 1;
	mutex_unlock(&mlxbf_pka_drv_lock);

	mlxbf_pka_dev->info = info;
	mlxbf_pka_dev->device = dev;
	info->flag = MLXBF_PKA_DRIVER_FLAG_DEVICE;
	mutex_init(&mlxbf_pka_dev->mutex);

	mlxbf_pka_dev->resource =
		platform_get_resource(pdev, IORESOURCE_MEM, 0);

	/* Set interrupts */
	ret = platform_get_irq(pdev, 0);
	mlxbf_pka_dev->irq = ret;
	if (ret == -ENXIO && of_node) {
		mlxbf_pka_dev->irq = MLXBF_PKA_IRQ_NONE;
	} else if (ret < 0) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DRIVER,
				"failed to get device %u IRQ\n",
				mlxbf_pka_dev->device_id);
		kfree(mlxbf_pka_dev);
		return ret;
	}

	/* Register IRQ */
	ret = mlxbf_pka_drv_register_irq(mlxbf_pka_dev);
	if (ret) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DRIVER,
				"failed to register device %u IRQ\n",
				mlxbf_pka_dev->device_id);
		kfree(mlxbf_pka_dev);
		return ret;
	}

	/*
	 * Retrieve the firmware identifier based on the device revision.
	 * Note that old platform firmware of BF1 does not support the
	 * "revision" property, thus set it by default.
	 */
	ret = device_property_read_u8(dev, "rev", &revision);
	if (ret < 0)
		revision = MLXBF_PKA_REVISION_1;

	switch (revision) {
	case MLXBF_PKA_REVISION_1:
		mlxbf_pka_dev->fw_id = MLXBF_PKA_FIRMWARE_IMAGE_0_ID;
		break;

	case MLXBF_PKA_REVISION_2:
		mlxbf_pka_dev->fw_id = MLXBF_PKA_FIRMWARE_IMAGE_1_ID;
		break;

	default:
		MLXBF_PKA_ERROR(MLXBF_PKA_DRIVER,
				"device %u revision %u is not supported\n",
				mlxbf_pka_dev->device_id, revision);
		kfree(mlxbf_pka_dev);
		return -EINVAL;
	}

	mutex_lock(&mlxbf_pka_drv_lock);
	ret = mlxbf_pka_drv_register_device(mlxbf_pka_dev);
	if (ret) {
		MLXBF_PKA_DEBUG(MLXBF_PKA_DRIVER,
				"failed to register shim id=%u\n",
				mlxbf_pka_dev->device_id);
		mutex_unlock(&mlxbf_pka_drv_lock);
		kfree(mlxbf_pka_dev);
		return ret;
	}
	mutex_unlock(&mlxbf_pka_drv_lock);

	/* Setup the TRNG, if needed */
	if (mlxbf_pka_dev_has_trng(mlxbf_pka_dev->shim)) {
		trng = &mlxbf_pka_dev->rng;
		trng->name = pdev->name;
		trng->read = mlxbf_pka_drv_rng_read;

		ret = hwrng_register(&mlxbf_pka_dev->rng);
		if (ret) {
			MLXBF_PKA_ERROR(MLXBF_PKA_DRIVER,
					"failed to register trng\n");
			kfree(mlxbf_pka_dev);
			return ret;
		}
	}

	info->priv = mlxbf_pka_dev;

	return 0;
}

static int mlxbf_pka_drv_remove_device(struct platform_device *pdev)
{
	struct mlxbf_pka_platdata *priv = platform_get_drvdata(pdev);
	struct mlxbf_pka_info *info = priv->info;
	struct mlxbf_pka_device *mlxbf_pka_dev =
		(struct mlxbf_pka_device *)info->priv;

	if (!mlxbf_pka_dev) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DRIVER,
				"failed to unregister device\n");
		return -EINVAL;
	}

	if (mlxbf_pka_dev_has_trng(mlxbf_pka_dev->shim))
		hwrng_unregister(&mlxbf_pka_dev->rng);

	if (mlxbf_pka_drv_unregister_device(mlxbf_pka_dev))
		MLXBF_PKA_ERROR(MLXBF_PKA_DRIVER,
				"failed to unregister device\n");

	return 0;
}

static int mlxbf_pka_drv_probe_ring_device(struct mlxbf_pka_info *info)
{
	struct mlxbf_pka_ring_device *mlxbf_pka_ring_dev;
	struct device *dev = info->dev;
	int ret;

	if (!info)
		return -EINVAL;

	mlxbf_pka_ring_dev = kzalloc(sizeof(*mlxbf_pka_ring_dev), GFP_KERNEL);
	if (!mlxbf_pka_ring_dev)
		return -ENOMEM;

	mutex_lock(&mlxbf_pka_drv_lock);
	mlxbf_pka_ring_device_cnt += 1;
	if (mlxbf_pka_ring_device_cnt > MLXBF_PKA_DRIVER_RING_DEV_MAX) {
		MLXBF_PKA_DEBUG(MLXBF_PKA_DRIVER,
				"cannot support %u ring devices\n",
				mlxbf_pka_ring_device_cnt);
		kfree(mlxbf_pka_ring_dev);
		mutex_unlock(&mlxbf_pka_drv_lock);
		return -EPERM;
	}
	mlxbf_pka_ring_dev->device_id = mlxbf_pka_ring_device_cnt - 1;
	mlxbf_pka_ring_dev->parent_device_id = mlxbf_pka_device_cnt - 1;
	mutex_unlock(&mlxbf_pka_drv_lock);

	mlxbf_pka_ring_dev->info = info;
	mlxbf_pka_ring_dev->device = dev;
	info->flag = MLXBF_PKA_DRIVER_FLAG_RING_DEVICE;
	mutex_init(&mlxbf_pka_ring_dev->mutex);

	ret = mlxbf_pka_drv_add_ring_device(mlxbf_pka_ring_dev);
	if (ret) {
		MLXBF_PKA_DEBUG(MLXBF_PKA_DRIVER,
			  "failed to add ring device %u\n",
			  mlxbf_pka_ring_dev->device_id);
		kfree(mlxbf_pka_ring_dev);
		return ret;
	}

	mutex_lock(&mlxbf_pka_drv_lock);
	/* Register ring device */
	ret = mlxbf_pka_drv_register_ring_device(mlxbf_pka_ring_dev);
	if (ret) {
		MLXBF_PKA_DEBUG(MLXBF_PKA_DRIVER,
			  "failed to register ring device %u\n",
			  mlxbf_pka_ring_dev->device_id);
		mutex_unlock(&mlxbf_pka_drv_lock);
		goto err_register_ring;
	}
	mutex_unlock(&mlxbf_pka_drv_lock);

	info->priv = mlxbf_pka_ring_dev;

	return 0;

 err_register_ring:
	mlxbf_pka_drv_del_ring_device(dev);
	kfree(mlxbf_pka_ring_dev);
	return ret;
}

static int mlxbf_pka_drv_remove_ring_device(struct platform_device *pdev)
{
	struct mlxbf_pka_ring_device *mlxbf_pka_ring_dev;
	struct device *dev = &pdev->dev;
	int ret;

	mlxbf_pka_ring_dev = mlxbf_pka_drv_del_ring_device(dev);
	if (mlxbf_pka_ring_dev) {
		ret = mlxbf_pka_drv_unregister_ring_device(mlxbf_pka_ring_dev);
		if (ret) {
			MLXBF_PKA_ERROR(MLXBF_PKA_DRIVER,
					"failed to unregister ring device %u\n",
					mlxbf_pka_ring_dev->device_id);
			return ret;
		}
		kfree(mlxbf_pka_ring_dev);
	}

	return 0;
}

static int mlxbf_pka_drv_acpi_probe(struct platform_device *pdev,
				    struct mlxbf_pka_info *info)
{
	struct device *dev = &pdev->dev;
	struct acpi_device *adev;
	int error;

	if (acpi_disabled)
		return -ENOENT;

	adev = ACPI_COMPANION(dev);
	if (!adev) {
		MLXBF_PKA_DEBUG(MLXBF_PKA_DRIVER,
				"ACPI companion device not found for %s\n",
				pdev->name);
		return -ENODEV;
	}

	info->acpihid = acpi_device_hid(adev);
	if (WARN_ON(!info->acpihid))
		return -EINVAL;

	if (!strcmp(info->acpihid, mlxbf_pka_ring_acpihid)) {
		error = mlxbf_pka_drv_probe_ring_device(info);
		if (error) {
			MLXBF_PKA_DEBUG(MLXBF_PKA_DRIVER,
					"failed to register ring device %s\n",
					pdev->name);
			return error;
		}
		MLXBF_PKA_DEBUG(MLXBF_PKA_DRIVER, "ring device %s probed\n",
				pdev->name);

	} else if (!strcmp(info->acpihid, mlxbf_pka_acpihid)) {
		error = mlxbf_pka_drv_probe_device(info);
		if (error) {
			MLXBF_PKA_DEBUG(MLXBF_PKA_DRIVER,
					"failed to register device %s\n",
					pdev->name);
			return error;
		}
		MLXBF_PKA_PRINT(MLXBF_PKA_DRIVER, "device %s probed\n",
				pdev->name);
	}

	return 0;
}

static int mlxbf_pka_drv_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct mlxbf_pka_platdata *priv;
	struct mlxbf_pka_info *info;
	int ret;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	spin_lock_init(&priv->lock);
	priv->pdev = pdev;
	/* interrupt is disabled to begin with */
	priv->irq_flags = 0;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		kfree(priv);
		return -ENOMEM;
	}

	info->name = pdev->name;
	info->version = MLXBF_PKA_DRIVER_VERSION;
	info->module = THIS_MODULE;
	info->dev = dev;

	priv->info = info;

	platform_set_drvdata(pdev, priv);

	/*
	 * There can be two kernel build combinations. One build where
	 * ACPI is not selected and another one with the ACPI.
	 *
	 * In the first case, 'mlxbf_pka_drv_acpi_probe' will return since
	 * acpi_disabled is 1. DT user will not see any kind of messages
	 * from ACPI.
	 *
	 * In the second case, both DT and ACPI is compiled in but the
	 * system is booting with any of these combinations.
	 *
	 * If the firmware is DT type, then acpi_disabled is 1. The ACPI
	 * probe routine terminates immediately without any messages.
	 *
	 * If the firmware is ACPI type, then acpi_disabled is 0. All other
	 * checks are valid checks. We cannot claim that this system is DT.
	 */
	ret = mlxbf_pka_drv_acpi_probe(pdev, info);

	if (ret) {
		MLXBF_PKA_DEBUG(MLXBF_PKA_DRIVER, "unknown device\n");
		return ret;
	}

	return 0;
}

static int mlxbf_pka_drv_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;

	/*
	 * Little hack here:
	 * The issue here is that the driver data structure which holds our
	 * initialized private data cannot be used when the 'pdev' arguments
	 * points to child device -i.e. ring device. Indeed, during the probe
	 * function we set an initialized structure called 'priv' as driver
	 * data for all platform devices including parents devices and child
	 * devices. This driver data is unique to each device - see call to
	 * 'platform_set_drvdata()'. However, when we add the child device to
	 * a ring group through 'ring_add_group_dev()' call, this function
	 * creates a new driver data for the device - i.e.  a 'ring_device'
	 * structure which includes a field called 'device_data' to hold the
	 * aforementionned initialized private data. So, to retrieve our
	 * private data, we must call 'dev_get_drvdata()' which returns the
	 * 'ring_device' struct and access its 'device_data' field. However,
	 * this cannot be done before determining if the 'pdev' is associated
	 * with a child device or a parent device.
	 * In order to deal with that we propose this little hack which uses
	 * the iommu_group to distinguich between parent and child devices.
	 * For now, let's say it is a customized solution that works for our
	 * case. Indeed, in the current design, the private data holds some
	 * infos that defines the type of the device. The intuitive way to do
	 * that is as following:
	 *
	 * struct mlxbf_pka_platdata *priv = platform_get_drvdata(pdev);
	 * struct mlxbf_pka_info     *info = priv->info;
	 *
	 * if (info->flag == MLXBF_PKA_DRIVER_FLAG_RING_DEVICE)
	 *      return mlxbf_pka_drv_remove_ring_device(info);
	 * if (info->flag == MLXBF_PKA_DRIVER_FLAG_DEVICE)
	 *      return mlxbf_pka_drv_remove_device(info);
	 *
	 * Since the returned private data of child devices -i.e ring devices
	 * corresponds to 'ring_device' structure, we cannot use it to
	 * differentiate between parent and child devices. This alternative
	 * solution is used instead.
	 */
	if (dev->iommu_group) {
		MLXBF_PKA_PRINT(MLXBF_PKA_DRIVER, "remove ring device %s\n",
				pdev->name);
		return mlxbf_pka_drv_remove_ring_device(pdev);
	}

	MLXBF_PKA_PRINT(MLXBF_PKA_DRIVER, "remove device %s\n", pdev->name);
	return mlxbf_pka_drv_remove_device(pdev);
}

static const struct of_device_id mlxbf_pka_drv_match[] = {
	{ .compatible = MLXBF_PKA_DEVICE_COMPAT },
	{ .compatible = MLXBF_PKA_RING_DEVICE_COMPAT },
	{}
};

MODULE_DEVICE_TABLE(of, mlxbf_pka_drv_match);

static const struct acpi_device_id mlxbf_pka_drv_acpi_ids[] = {
	{ MLXBF_PKA_DEVICE_ACPIHID, 0 },
	{ MLXBF_PKA_RING_DEVICE_ACPIHID, 0 },
	{},
};

MODULE_DEVICE_TABLE(acpi, mlxbf_pka_drv_acpi_ids);

static struct platform_driver mlxbf_pka_drv = {
	.driver  = {
		   .name = MLXBF_PKA_DRIVER_NAME,
		   .of_match_table   = of_match_ptr(mlxbf_pka_drv_match),
		   .acpi_match_table = ACPI_PTR(mlxbf_pka_drv_acpi_ids),
		   },
	.probe  = mlxbf_pka_drv_probe,
	.remove = mlxbf_pka_drv_remove,
};

/* Initialize the module - Register the mlxbf_pka platform driver */
static int __init mlxbf_pka_drv_register(void)
{
	int ret;

	ret = mlxbf_pka_drv_init_class();
	if (ret) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DRIVER, "failed to create class\n");
		return ret;
	}

	ret = platform_driver_register(&mlxbf_pka_drv);
	if (ret) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DRIVER, "failed to register platform driver\n");
		return ret;
	}

	MLXBF_PKA_PRINT(MLXBF_PKA_DRIVER, "version: " MLXBF_PKA_DRIVER_VERSION "\n");

	return 0;
}

/* Cleanup the module - unregister the mlxbf_pka platform driver */
static void __exit mlxbf_pka_drv_unregister(void)
{
	MLXBF_PKA_DEBUG(MLXBF_PKA_DRIVER, "unregister platform driver\n");
	platform_driver_unregister(&mlxbf_pka_drv);
	mlxbf_pka_drv_destroy_class();
}

module_init(mlxbf_pka_drv_register);
module_exit(mlxbf_pka_drv_unregister);

MODULE_DESCRIPTION(MLXBF_PKA_DRIVER_DESCRIPTION);
MODULE_LICENSE("Dual BSD/GPL");
