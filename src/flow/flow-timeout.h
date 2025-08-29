#ifndef __FLOW_TIMEOUT_H__
#define __FLOW_TIMEOUT_H__

void FlowForceReassemblyForFlow(Flow *f);
int FlowForceReassemblyNeedReassembly(Flow *f);
void FlowForceReassembly(void);
void FlowForceReassemblySetup(int detect_disabled);

#endif /* __FLOW_TIMEOUT_H__ */
