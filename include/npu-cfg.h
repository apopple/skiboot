#ifndef __NPU_CFG_H
#define __NPU_CFG_H

/* The config space of NPU device is emulated. We have different
 * bits to represent config register properties: readonly, write-
 * one-to-clear.
 */
#define CONFIG_SPACE_MAX	3
#define CONFIG_SPACE_NORMAL      0
#define CONFIG_SPACE_RDONLY      1
#define CONFIG_SPACE_W1CLR       2

/* Bytes of the emulated NPU PCI device config space. We are
 * emulating PCI express device, not legacy one
 */
#define CONFIG_SPACE_SIZE	0x100

/*
 * This struct is used to represent an emulated configuration space
 * for NVLink 1.0 and NVLink 2.0.
 */
struct config_space {
	uint8_t			*config[CONFIG_SPACE_MAX];
	struct list_head	traps;
};

/* Config space access trap. */
struct config_space_trap {
	uint32_t		start;
	uint32_t		end;
	void			*data;
	int64_t			(*read)(struct config_space *cfg,
					struct config_space_trap *trap,
					uint32_t offset,
					uint32_t size,
					uint32_t *data);
	int64_t			(*write)(struct config_space *cfg,
					 struct config_space_trap *trap,
					 uint32_t offset,
					 uint32_t size,
					 uint32_t data);
	struct list_node	link;
};

void config_space_read_raw(struct config_space *cfg,
			   uint32_t index,
			   uint32_t offset,
			   uint32_t size,
			   uint32_t *val);

void config_space_write_raw(struct config_space *cfg,
			    uint32_t index,
			    uint32_t offset,
			    uint32_t size,
			    uint32_t val);

int64_t config_space_read(struct config_space *cfg,
			  uint32_t offset, uint32_t *data,
			  size_t size);

int64_t config_space_write(struct config_space *cfg,
			   uint32_t offset, uint32_t data,
			   size_t size);

void config_space_add_trap(struct config_space *cfg, uint32_t start,
			   uint32_t size, void *data,
			   int64_t (*read)(struct config_space *,
					   struct config_space_trap *,
					   uint32_t,
					   uint32_t,
					   uint32_t *),
			   int64_t (*write)(struct config_space *,
					    struct config_space_trap *,
					    uint32_t,
					    uint32_t,
					    uint32_t));

void config_space_init(struct config_space *cfg);

/* PCI config raw accessors */
#define NPU_DEV_CFG_NORMAL_RD(d, o, s, v)	\
	config_space_read_raw(&d->config_space, CONFIG_SPACE_NORMAL, o, s, v)
#define NPU_DEV_CFG_NORMAL_WR(d, o, s, v)	\
	config_space_write_raw(&d->config_space, CONFIG_SPACE_NORMAL, o, s, v)
#define NPU_DEV_CFG_RDONLY_RD(d, o, s, v)	\
	config_space_read_raw(&d->config_space, CONFIG_SPACE_RDONLY, o, s, v)
#define NPU_DEV_CFG_RDONLY_WR(d, o, s, v)	\
	config_space_write_raw(&d->config_space, CONFIG_SPACE_RDONLY, o, s, v)
#define NPU_DEV_CFG_W1CLR_RD(d, o, s, v)		\
	config_space_read_raw(&d->config_space, CONFIG_SPACE_W1CLR, o, s, v)
#define NPU_DEV_CFG_W1CLR_WR(d, o, s, v)		\
	config_space_write_raw(&d->config_space, CONFIG_SPACE_W1CLR, o, s, v)

#define NPU_DEV_CFG_INIT(d, o, s, v, ro, w1)		\
	do {						\
		NPU_DEV_CFG_NORMAL_WR(d, o, s, v);	\
		NPU_DEV_CFG_RDONLY_WR(d, o, s, ro);	\
		NPU_DEV_CFG_W1CLR_WR(d, o, s, w1);	\
	} while(0)

#define NPU_DEV_CFG_INIT_RO(d, o, s, v)			\
	NPU_DEV_CFG_INIT(d, o, s, v, 0xffffffff, 0)

#define NPU_DEV_CFG_READ(size, type, cb)       				\
static int64_t config_space_read##size(struct phb *phb, uint32_t bdfn,	\
				       uint32_t offset, type *data)	\
{									\
	struct config_space *cfg;					\
	int64_t rc;							\
	uint32_t val;							\
									\
	cfg = cb(phb, bdfn);						\
	if (!cfg)							\
		return OPAL_PARAMETER;					\
									\
	/* Data returned upon errors */					\
	rc = config_space_read(cfg, offset, &val, sizeof(*data));	\
	*data = (type)val;						\
	return rc;							\
}

#define NPU_DEV_CFG_WRITE(size, type, cb)				\
static int64_t config_space_write##size(struct phb *phb, uint32_t bdfn,	\
					uint32_t offset, type data)	\
{									\
	struct config_space *cfg;					\
									\
	cfg = cb(phb, bdfn);						\
	if (!cfg)							\
		return OPAL_PARAMETER;					\
									\
	return config_space_write(cfg, offset, data, sizeof(data));	\
}

#endif
