#ifndef __FLOW_MANAGER_H__
#define __FLOW_MANAGER_H__

/** flow manager scheduling condition */
extern pthread_cond_t flow_manager_ctrl_cond;
extern pthread_mutex_t flow_manager_ctrl_mutex;
#define FlowWakeupFlowManagerThread() SCCtrlCondSignal(&flow_manager_ctrl_cond)
extern pthread_cond_t flow_recycler_ctrl_cond;
extern pthread_mutex_t flow_recycler_ctrl_mutex;
#define FlowWakeupFlowRecyclerThread() SCCtrlCondSignal(&flow_recycler_ctrl_cond)

#define FlowTimeoutsReset() FlowTimeoutsInit()

void FlowTimeoutsInit(void);
void FlowTimeoutsEmergency(void);
void FlowManagerThreadSpawn(void);
void FlowDisableFlowManagerThread(void);
void FlowRecyclerThreadSpawn(void);
void FlowDisableFlowRecyclerThread(void);
void TmModuleFlowManagerRegister (void);
void TmModuleFlowRecyclerRegister (void);

#endif /* __FLOW_MANAGER_H__ */
