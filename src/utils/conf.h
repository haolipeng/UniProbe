#ifndef NET_THREAT_DETECT_CONF_H
#define NET_THREAT_DETECT_CONF_H
#include "queue.h"
#include <stddef.h>
#include <stdint.h>

#define DEFAULT_LOG_DIR "/var/log/suricata"
/**
 * Structure of a configuration parameter.
 */
typedef struct ConfNode_ {
  char *name;
  char *val;

  int is_seq;

  /**< Flag that sets this nodes value as final. */
  int final;

  struct ConfNode_ *parent;
  TAILQ_HEAD(, ConfNode_) head;
  TAILQ_ENTRY(ConfNode_) next;
} ConfNode;

void ConfInit(void);

ConfNode *ConfNodeNew(void);
void ConfNodeFree(ConfNode *node);

int ConfSetFinal(const char *name, const char *val);

ConfNode *ConfGetNode(const char *name);

int ConfGet(const char *name, const char **vptr);
int ConfGetValue(const char *name, const char **vptr);
int ConfGetInt(const char *name, intmax_t *val);
int ConfGetBool(const char *name, int *val);

ConfNode *ConfNodeLookupChild(const ConfNode *node, const char *key);
const char *ConfNodeLookupChildValue(const ConfNode *node, const char *key);
void ConfNodePrune(ConfNode *node);
ConfNode *ConfGetRootNode(void);
int ConfSet(const char *name, const char *val);

int ConfValIsFalse(const char *val);
int ConfValIsTrue(const char *val);
int ConfGetChildValue(const ConfNode *base, const char *name, const char **vptr);
int ConfGetChildValueBool(const ConfNode *base, const char *name, int *val);
int ConfGetChildValueInt(const ConfNode *base, const char *name, intmax_t *val);

int ConfGetChildValueWithDefault(const ConfNode *base, const ConfNode *dflt, const char *name, const char **vptr);
int ConfGetChildValueIntWithDefault(const ConfNode *base, const ConfNode *dflt, const char *name, intmax_t *val);
int ConfGetChildValueBoolWithDefault(const ConfNode *base, const ConfNode *dflt, const char *name, int *val);
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif // NET_THREAT_DETECT_CONF_H
