#include <ntdef.h>
#include <ntifs.h>


DRIVER_INITIALIZE DriverEntry;
#pragma alloc_text(INIT, DriverEntry)
#define PROCESS_QUERY_LIMITED_INFORMATION      0x1000



typedef struct _OB_REG_CONTEXT {
	USHORT Version;
	UNICODE_STRING Altitude;
	USHORT ulIndex;
	OB_OPERATION_REGISTRATION *OperationRegistration;
} REG_CONTEXT, *PREG_CONTEXT;

UNICODE_STRING SACDriverName, SACSymbolName;
PVOID ObHandle = NULL;

//ULONG ProtectedProcess1 = 516; // The Usermode Anti Cheat PID
ULONG ProtectedProcess = 0; // Your game's PID
ULONG UsermodeAntiCheat = 0; // Your game's PID
ULONG Lsass = 0;
ULONG Csrss1 = 0;
ULONG Csrss2 = 0;
// This function will be called when a handle is about to be created
OB_PREOP_CALLBACK_STATUS PreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	if (UsermodeAntiCheat == 0)
		return OB_PREOP_SUCCESS;

	if (ProtectedProcess == 0)
		return OB_PREOP_SUCCESS;

	if (Lsass == 0)
		return OB_PREOP_SUCCESS;

	if (Csrss1 == 0)
		return OB_PREOP_SUCCESS;

	if (Csrss2 == 0)
		return OB_PREOP_SUCCESS;

	PEPROCESS LsassProcess;
	PEPROCESS Csrss1Process;
	PEPROCESS Csrss2Process;
	PEPROCESS ProtectedProcessProcess;

	PEPROCESS OpenedProcess = (PEPROCESS)OperationInformation->Object,
		CurrentProcess = PsGetCurrentProcess();

	ULONG ulProcessId = PsGetProcessId(OpenedProcess);

	PsLookupProcessByProcessId(ProtectedProcess, &ProtectedProcessProcess); // Getting the PEPROCESS using the PID 
	PsLookupProcessByProcessId(Lsass, &LsassProcess); // Getting the PEPROCESS using the PID 
	PsLookupProcessByProcessId(Csrss1, &Csrss1Process); // Getting the PEPROCESS using the PID 
	PsLookupProcessByProcessId(Csrss2, &Csrss2Process); // Getting the PEPROCESS using the PID 

	if (OpenedProcess == LsassProcess)// Making sure to not strip lsass's Handle, will cause BSOD
		return OB_PREOP_SUCCESS;

	if (OpenedProcess == Csrss1Process) // Making sure to not strip csrss's Handle, will cause BSOD
		return OB_PREOP_SUCCESS;

	if (OpenedProcess == Csrss2Process)// Making sure to not strip csrss's Handle, will cause BSOD
		return OB_PREOP_SUCCESS;

	if (OpenedProcess == CurrentProcess)
		return OB_PREOP_SUCCESS;

	if (OpenedProcess == ProtectedProcess)
		return OB_PREOP_SUCCESS;

	if (OpenedProcess == UsermodeAntiCheat)
		return OB_PREOP_SUCCESS;

	// Allow operations from within the kernel
	if (OperationInformation->KernelHandle)
		return OB_PREOP_SUCCESS;


	// PsGetProcessId((PEPROCESS)OperationInformation->Object) equals to the created handle's PID, so if the created Handle equals to the protected process's PID, strip
	if (PsGetProcessId((PEPROCESS)OperationInformation->Object) == ProtectedProcess || PsGetProcessId((PEPROCESS)OperationInformation->Object) == UsermodeAntiCheat)
	{

		if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) // striping handle 
		{
			OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = (SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION);
		}
		else
		{
			OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = (SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION);
		}

		return OB_PREOP_SUCCESS;
	}
}

// This happens after everything. 
VOID PostCallBack(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION OperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	UNREFERENCED_PARAMETER(OperationInformation);
}

// Unregistering the callback.
VOID UnRegister()
{
	ObUnRegisterCallbacks(ObHandle); // unregistering the callback
	ObHandle = NULL;
}

// Terminating a process of your choice using the PID, usefull if the cheat is also using a driver to strip it's handles and therefore you can forcefully close it using the driver
NTSTATUS TerminatingProcess(ULONG targetPid)
{
	NTSTATUS NtRet = STATUS_SUCCESS;
	PEPROCESS PeProc = { 0 };
	NtRet = PsLookupProcessByProcessId(targetPid, &PeProc);
	if (NtRet != STATUS_SUCCESS)
	{
		return NtRet;
	}
	HANDLE ProcessHandle;
	NtRet = ObOpenObjectByPointer(PeProc, NULL, NULL, 25, *PsProcessType, KernelMode, &ProcessHandle);
	if (NtRet != STATUS_SUCCESS)
	{
		return NtRet;
	}
	ZwTerminateProcess(ProcessHandle, 0);
	//ZwClose(ProcessHandle);
	return NtRet;
}

NTSTATUS DriverDispatchRoutine(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	PVOID buffer;
	NTSTATUS NtStatus = STATUS_SUCCESS;
	PIO_STACK_LOCATION pIo;
	pIo = IoGetCurrentIrpStackLocation(pIrp);
	pIrp->IoStatus.Information = 0;
	switch (pIo->MajorFunction)
	{
	case IRP_MJ_CREATE:
		NtStatus = STATUS_SUCCESS;
		break;
	case IRP_MJ_READ:
		NtStatus = STATUS_SUCCESS;
		break;
	case IRP_MJ_WRITE:
		break;
	case IRP_MJ_CLOSE:
		NtStatus = STATUS_SUCCESS;
		break;
	default:
		NtStatus = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return NtStatus;
}

// This will be called, if the driver is unloaded or just returns something
VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{

	UnRegister();

	IoDeleteSymbolicLink(&SACSymbolName);
	IoDeleteDevice(pDriverObject->DeviceObject);

	DbgPrint("Unload called!");
}

void RemoveTheLinks(PLIST_ENTRY Current)
{

	PLIST_ENTRY Previous, Next;

	Previous = (Current->Blink);
	Next = (Current->Flink);

	// Loop over self (connect previous with next)
	Previous->Flink = Next;
	Next->Blink = Previous;

	// Re-write the current LIST_ENTRY to point to itself (avoiding BSOD)
	Current->Blink = (PLIST_ENTRY)&Current->Flink;
	Current->Flink = (PLIST_ENTRY)&Current->Flink;

	return;

}

ULONG LookForProcessOffsets()
{


	ULONG pid_ofs = 0; // The offset we're looking for
	int idx = 0;                // Index 
	ULONG pids[3];				// List of PIDs for our 3 processes
	PEPROCESS eprocs[3];		// Process list, will contain 3 processes

								//Select 3 process PIDs and get their EPROCESS Pointer
	for (int i = 16; idx<3; i += 4)
	{
		if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)i, &eprocs[idx])))
		{
			pids[idx] = i;
			idx++;
		}
	}


	/*
	Go through the EPROCESS structure and look for the PID
	we can start at 0x20 because UniqueProcessId should
	not be in the first 0x20 bytes,
	also we should stop after 0x300 bytes with no success
	*/

	for (int i = 0x20; i<0x300; i += 4)
	{
		if ((*(ULONG *)((UCHAR *)eprocs[0] + i) == pids[0])
			&& (*(ULONG *)((UCHAR *)eprocs[1] + i) == pids[1])
			&& (*(ULONG *)((UCHAR *)eprocs[2] + i) == pids[2]))
		{
			pid_ofs = i;
			break;
		}
	}

	ObDereferenceObject(eprocs[0]);
	ObDereferenceObject(eprocs[1]);
	ObDereferenceObject(eprocs[2]);


	return pid_ofs;
}

// hides any process from the task bar and everything. only works for about 10 - 30 mins before patch guard is triggered and BSOD happens
PCHAR GhostProcess(UINT32 pid)
{


	LPSTR result = ExAllocatePool(NonPagedPool, sizeof(ULONG) + 20);;


	// Get PID offset nt!_EPROCESS.UniqueProcessId
	ULONG PID_OFFSET = LookForProcessOffsets();

	// Check if offset discovery was successful 
	if (PID_OFFSET == 0) {
		return (PCHAR)"Could not find PID offset!";
	}

	// Get LIST_ENTRY offset nt!_EPROCESS.ActiveProcessLinks
	ULONG LIST_OFFSET = PID_OFFSET;


	// Check Architecture using pointer size
	INT_PTR ptr;

	// Ptr size 8 if compiled for a 64-bit machine, 4 if compiled for 32-bit machine
	LIST_OFFSET += sizeof(ptr);

	// Get current process
	PEPROCESS CurrentEPROCESS = PsGetCurrentProcess();

	// Initialize other variables
	PLIST_ENTRY CurrentList = (PLIST_ENTRY)((ULONG_PTR)CurrentEPROCESS + LIST_OFFSET);
	PUINT32 CurrentPID = (PUINT32)((ULONG_PTR)CurrentEPROCESS + PID_OFFSET);

	// Check self 
	if (*(UINT32 *)CurrentPID == pid) {
		RemoveTheLinks(CurrentList);
		return (PCHAR)result;
	}

	// Record the starting position
	PEPROCESS StartProcess = CurrentEPROCESS;

	// Move to next item
	CurrentEPROCESS = (PEPROCESS)((ULONG_PTR)CurrentList->Flink - LIST_OFFSET);
	CurrentPID = (PUINT32)((ULONG_PTR)CurrentEPROCESS + PID_OFFSET);
	CurrentList = (PLIST_ENTRY)((ULONG_PTR)CurrentEPROCESS + LIST_OFFSET);

	// Loop until we find the right process to remove
	// Or until we circle back
	while ((ULONG_PTR)StartProcess != (ULONG_PTR)CurrentEPROCESS)
	{

		// Check item
		if (*(UINT32 *)CurrentPID == pid) {
			RemoveTheLinks(CurrentList);
			return (PCHAR)result;
		}

		// Move to next item
		CurrentEPROCESS = (PEPROCESS)((ULONG_PTR)CurrentList->Flink - LIST_OFFSET);
		CurrentPID = (PUINT32)((ULONG_PTR)CurrentEPROCESS + PID_OFFSET);
		CurrentList = (PLIST_ENTRY)((ULONG_PTR)CurrentEPROCESS + LIST_OFFSET);
	}

	return (PCHAR)result;
}

PDEVICE_OBJECT g_MyDevice; // Global pointer to our device object


NTSTATUS Create(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS Close(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

// Request to read from usermode
#define IO_READ_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0701 /* Our Custom Code */, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// Request to write virtual user memory (memory of a program) from kernel space
#define IO_UNLOADDRIVER_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0702 /* Our Custom Code */, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)


// datatype for read request
typedef struct _KERNEL_READ_REQUEST
{
	ULONG CSGO;

	ULONG LSASS;
	ULONG CSRSS;
	ULONG CSRSS2;
	ULONG UsermodeProgram;
	ULONG TerminatePrograms;

} KERNEL_READ_REQUEST, *PKERNEL_READ_REQUEST;

// database for unload details
typedef struct _KERNEL_UNLOADDRIVER
{
	ULONG UnloadDriver;

} KERNEL_UNLOADDRIVER, *PKERNEL_UNLOADDRIVER;

ULONG TerminateProcess = 0;
BOOLEAN  UnloadDriver = FALSE;
NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS Status;
	ULONG BytesIO = 0;

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

	// Code received from user space
	ULONG ControlCode = stack->Parameters.DeviceIoControl.IoControlCode;
	if (ControlCode == IO_UNLOADDRIVER_REQUEST)
	{
		PKERNEL_UNLOADDRIVER ReadInput = (PKERNEL_UNLOADDRIVER)Irp->AssociatedIrp.SystemBuffer;

		if (ReadInput->UnloadDriver)
		{
			UnloadDriver = TRUE;
		}
	}
	if (ControlCode == IO_READ_REQUEST)
	{
		// Get the input buffer & format it to our struct
		PKERNEL_READ_REQUEST ReadInput = (PKERNEL_READ_REQUEST)Irp->AssociatedIrp.SystemBuffer;

		if (ReadInput->UsermodeProgram != 0)
		{
			UsermodeAntiCheat = ReadInput->UsermodeProgram;
		}

		if (ReadInput->CSGO != 0)
		{
			ProtectedProcess = ReadInput->CSGO;
		}

		if (ReadInput->LSASS != 0)
		{
			Lsass = ReadInput->LSASS;
		}

		if (ReadInput->CSRSS != 0)
		{
			Csrss1 = ReadInput->CSRSS;
		}

		if (ReadInput->CSRSS2 != 0)
		{
			Csrss2 = ReadInput->CSRSS2;
		}

		if (ReadInput->TerminatePrograms != 0)
		{
			TerminateProcess = ReadInput->TerminatePrograms;
		}

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(KERNEL_READ_REQUEST);
	}
	else
	{
		// if the code is unknown
		Status = STATUS_INVALID_PARAMETER;
		BytesIO = 0;
	}

	// Complete the request
	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = BytesIO;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Status;
}

// Enabling the callback,
VOID EnableCallBack()
{
	NTSTATUS NtRet1 = STATUS_SUCCESS;
	OB_OPERATION_REGISTRATION OBOperationRegistration;
	OB_CALLBACK_REGISTRATION OBOCallbackRegistration;
	REG_CONTEXT regContext;
	UNICODE_STRING usAltitude;
	memset(&OBOperationRegistration, 0, sizeof(OB_OPERATION_REGISTRATION));
	memset(&OBOCallbackRegistration, 0, sizeof(OB_CALLBACK_REGISTRATION));
	memset(&regContext, 0, sizeof(REG_CONTEXT));
	regContext.ulIndex = 1;
	regContext.Version = 120;
	RtlInitUnicodeString(&usAltitude, L"1000");

	if ((USHORT)ObGetFilterVersion() == OB_FLT_REGISTRATION_VERSION)
	{
		OBOperationRegistration.ObjectType = PsProcessType; // Use To Strip Handle Permissions For Threads PsThreadType
		OBOperationRegistration.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
		OBOperationRegistration.PostOperation = PostCallBack; // Giving the function which happens after creating
		OBOperationRegistration.PreOperation = PreCallback; // Giving the function which happens before creating

															// Setting the altitude of the driver
		OBOCallbackRegistration.Altitude = usAltitude;
		OBOCallbackRegistration.OperationRegistration = &OBOperationRegistration;
		OBOCallbackRegistration.RegistrationContext = &regContext;
		OBOCallbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
		OBOCallbackRegistration.OperationRegistrationCount = (USHORT)1;

		NtRet1 = ObRegisterCallbacks(&OBOCallbackRegistration, &ObHandle); // Register The CallBack
	}

	if (TerminateProcess != 0)
	{
		TerminatingProcess(TerminateProcess);
		TerminateProcess = 0;
	}
}

// Driver's Main function. This will be called and looped through till returned, or unloaded.
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pUniStr)
{

	NTSTATUS NtRet = STATUS_SUCCESS;
	PDEVICE_OBJECT pDeviceObj;
	RtlInitUnicodeString(&SACDriverName, L"\\Device\\SACDriver"); // Giving the driver a name
	RtlInitUnicodeString(&SACSymbolName, L"\\DosDevices\\SACDriver"); // Giving the driver a symbol
	UNICODE_STRING deviceNameUnicodeString, deviceSymLinkUnicodeString;
	NTSTATUS NtRet2 = IoCreateDevice(pDriverObject, 0, &SACDriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObj);
	if (NtRet2 == STATUS_SUCCESS)
	{
		ULONG i;
		for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
		{
			pDriverObject->MajorFunction[i] = DriverDispatchRoutine;
		}


		IoCreateSymbolicLink(&SACSymbolName, &SACDriverName);

		pDriverObject->MajorFunction[IRP_MJ_CREATE] = Create;
		pDriverObject->MajorFunction[IRP_MJ_CLOSE] = Close;
		pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl;

		pDeviceObj->Flags |= DO_DIRECT_IO;
		pDeviceObj->Flags &= (~DO_DEVICE_INITIALIZING);
	}


	pDriverObject->DriverUnload = DriverUnload; // Telling the driver, this is the unload function
	EnableCallBack();

	if (UnloadDriver)
	{
		return NtRet;
	}

	//return NtRet;
}
