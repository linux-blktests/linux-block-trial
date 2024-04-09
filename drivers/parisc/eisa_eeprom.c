// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 *    EISA "eeprom" support routines
 *
 *    Copyright (C) 2001 Thomas Bogendoerfer <tsbogend at parisc-linux.org>
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <asm/io.h>
#include <linux/uaccess.h>
#include <asm/eisa_eeprom.h>

static loff_t eisa_eeprom_llseek(struct file *file, loff_t offset, int origin)
{
	return fixed_size_llseek(file, offset, origin, HPEE_MAX_LENGTH);
}

static ssize_t eisa_eeprom_read(struct kiocb *iocb, struct iov_iter *to)
{
	size_t count = iov_iter_count(to);
	unsigned char *tmp;
	ssize_t ret;
	int i;
	
	if (iocb->ki_pos < 0 || iocb->ki_pos >= HPEE_MAX_LENGTH)
		return 0;
	
	count = iocb->ki_pos + count < HPEE_MAX_LENGTH ? count : HPEE_MAX_LENGTH - iocb->ki_pos;
	tmp = kmalloc(count, GFP_KERNEL);
	if (tmp) {
		for (i = 0; i < count; i++)
			tmp[i] = readb(eisa_eeprom_addr+iocb->ki_pos++);

		if (!copy_to_iter_full(tmp, count, to))
			ret = -EFAULT;
		else
			ret = count;
		kfree (tmp);
	} else
		ret = -ENOMEM;
	
	return ret;
}

static int eisa_eeprom_open(struct inode *inode, struct file *file)
{
	if (file->f_mode & FMODE_WRITE)
		return -EINVAL;
   
	return 0;
}

static int eisa_eeprom_release(struct inode *inode, struct file *file)
{
	return 0;
}

/*
 *	The various file operations we support.
 */
static const struct file_operations eisa_eeprom_fops = {
	.owner =	THIS_MODULE,
	.llseek =	eisa_eeprom_llseek,
	.read_iter =	eisa_eeprom_read,
	.open =		eisa_eeprom_open,
	.release =	eisa_eeprom_release,
};

static struct miscdevice eisa_eeprom_dev = {
	EISA_EEPROM_MINOR,
	"eisa_eeprom",
	&eisa_eeprom_fops
};

static int __init eisa_eeprom_init(void)
{
	int retval;

	if (!eisa_eeprom_addr)
		return -ENODEV;

	retval = misc_register(&eisa_eeprom_dev);
	if (retval < 0) {
		printk(KERN_ERR "EISA EEPROM: cannot register misc device.\n");
		return retval;
	}

	printk(KERN_INFO "EISA EEPROM at 0x%px\n", eisa_eeprom_addr);
	return 0;
}

MODULE_LICENSE("GPL");

module_init(eisa_eeprom_init);
