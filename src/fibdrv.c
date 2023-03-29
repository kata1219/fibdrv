#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kdev_t.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/sysfs.h>

#include "bignum.h"

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("National Cheng Kung University, Taiwan");
MODULE_DESCRIPTION("Fibonacci engine driver");
MODULE_VERSION("0.1");

#define DEV_FIBONACCI_NAME "fibonacci"

/* MAX_LENGTH is set to 92 because
 * ssize_t can't fit the number > 92
 */
#define MAX_LENGTH 500

// static int foo = 1;

/*
 * The "foo" file where a static variable is read from and written to.
 */
// static ssize_t foo_show(struct kobject *kobj,
//                         struct kobj_attribute *attr,
//                         char *buf)
// {
//     return sysfs_emit(buf, "%d\n", foo);
// }

// static ssize_t foo_store(struct kobject *kobj,
//                          struct kobj_attribute *attr,
//                          const char *buf,
//                          size_t count)
// {
//     int ret;

//     ret = kstrtoint(buf, 10, &foo);
//     if (ret < 0)
//         return ret;

//     return count;
// }


// /* Sysfs attributes cannot be world-writable. */
// static struct kobj_attribute foo_attribute =
//     __ATTR(foo, 0664, foo_show, foo_store);


// /*
//  * Create a group of attributes so that we can create and destroy them all
//  * at once.
//  */
// static struct attribute *attrs[] = {
//     &foo_attribute.attr,
//     NULL, /* need to NULL terminate the list of attributes */
// };

/*
 * An unnamed attribute group will put all of the attributes directly in
 * the kobject directory.  If we specify a name, a subdirectory will be
 * created for the attributes with the directory being the name of the
 * attribute group.
 */
// static struct attribute_group attr_group = {
//     .attrs = attrs,
// };

static dev_t fib_dev = 0;
static struct cdev *fib_cdev;
static struct class *fib_class;
static DEFINE_MUTEX(fib_mutex);
// static struct kobject *fib_kobj;

// static long long fib_sequence(long long k)
// {
//     /* FIXME: C99 variable-length array (VLA) is not allowed in Linux kernel.
//     */ long long f[k + 2];

//     f[0] = 0;
//     f[1] = 1;

//     for (int i = 2; i <= k; i++) {
//         f[i] = f[i - 1] + f[i - 2];
//     }

//     return f[k];
// }

static int fib_open(struct inode *inode, struct file *file)
{
    if (!mutex_trylock(&fib_mutex)) {
        printk(KERN_ALERT "fibdrv is in use");
        return -EBUSY;
    }
    return 0;
}

static int fib_release(struct inode *inode, struct file *file)
{
    mutex_unlock(&fib_mutex);
    return 0;
}

// /* calculate the fibonacci number at given offset */
// static ssize_t fib_read(struct file *file,
//                         char *buf,
//                         size_t size,
//                         loff_t *offset)
// {
//     return (ssize_t) fib_sequence(*offset);
// }

/* calculate the fibonacci number at given offset */
static ssize_t fib_read(struct file *file,
                        char __user *buf,
                        size_t size,
                        loff_t *offset)
{
    char *output = bn_fast_doubling(*offset);
    ssize_t len = strlen(output) + 1;
    int ret = 0;
    printk(KERN_INFO "%ld HERE\n", size);
    // foo_store(fib_kobj, &foo_attribute, "hello", 5);
    // char buffer[90];
    // foo_show(fib_kobj, &foo_attribute, buffer);

    ret = copy_to_user(buf, output, len);
    if (ret)
        return -EFAULT;

    kfree(output);
    return len;
}

/* write operation is skipped */
static ssize_t fib_write(struct file *file,
                         const char *buf,
                         size_t size,
                         loff_t *offset)
{
    return 1;
}

static loff_t fib_device_lseek(struct file *file, loff_t offset, int orig)
{
    loff_t new_pos = 0;
    switch (orig) {
    case 0: /* SEEK_SET: */
        new_pos = offset;
        break;
    case 1: /* SEEK_CUR: */
        new_pos = file->f_pos + offset;
        break;
    case 2: /* SEEK_END: */
        new_pos = MAX_LENGTH - offset;
        break;
    }

    if (new_pos > MAX_LENGTH)
        new_pos = MAX_LENGTH;  // max case
    if (new_pos < 0)
        new_pos = 0;        // min case
    file->f_pos = new_pos;  // This is what we'll use now
    return new_pos;
}

const struct file_operations fib_fops = {
    .owner = THIS_MODULE,
    .read = fib_read,
    .write = fib_write,
    .open = fib_open,
    .release = fib_release,
    .llseek = fib_device_lseek,
};


static int __init init_fib_dev(void)
{
    int rc = 0;

    mutex_init(&fib_mutex);

    // fib_kobj = kobject_create_and_add("kobject_fib", kernel_kobj);
    // if (!fib_kobj)
    //     return -ENOMEM;

    // /* Create the files associated with this kobject */
    // rc = sysfs_create_group(fib_kobj, &attr_group);
    // if (rc)
    //     kobject_put(fib_kobj);

    // Let's register the device
    // This will dynamically allocate the major number
    rc = alloc_chrdev_region(&fib_dev, 0, 1, DEV_FIBONACCI_NAME);

    if (rc < 0) {
        printk(KERN_ALERT
               "Failed to register the fibonacci char device. rc = %i",
               rc);
        return rc;
    }

    fib_cdev = cdev_alloc();
    if (fib_cdev == NULL) {
        printk(KERN_ALERT "Failed to alloc cdev");
        rc = -1;
        goto failed_cdev;
    }
    fib_cdev->ops = &fib_fops;
    rc = cdev_add(fib_cdev, fib_dev, 1);

    if (rc < 0) {
        printk(KERN_ALERT "Failed to add cdev");
        rc = -2;
        goto failed_cdev;
    }

    fib_class = class_create(THIS_MODULE, DEV_FIBONACCI_NAME);

    if (!fib_class) {
        printk(KERN_ALERT "Failed to create device class");
        rc = -3;
        goto failed_class_create;
    }

    if (!device_create(fib_class, NULL, fib_dev, NULL, DEV_FIBONACCI_NAME)) {
        printk(KERN_ALERT "Failed to create device");
        rc = -4;
        goto failed_device_create;
    }
    return rc;
failed_device_create:
    class_destroy(fib_class);
failed_class_create:
    cdev_del(fib_cdev);
failed_cdev:
    unregister_chrdev_region(fib_dev, 1);
    return rc;
}

static void __exit exit_fib_dev(void)
{
    // kobject_put(fib_kobj);
    mutex_destroy(&fib_mutex);
    device_destroy(fib_class, fib_dev);
    class_destroy(fib_class);
    cdev_del(fib_cdev);
    unregister_chrdev_region(fib_dev, 1);
}

module_init(init_fib_dev);
module_exit(exit_fib_dev);
