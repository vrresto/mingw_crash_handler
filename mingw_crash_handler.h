#ifndef MINGW_CRASH_HANDLER_H
#define MINGW_CRASH_HANDLER_H

#include <windef.h>

struct MingwCrashHandlerInterface
{
  virtual void crashHandler(PEXCEPTION_POINTERS pExceptionInfo) = 0;
  virtual void dumpStack(const CONTEXT*) = 0;
  virtual void setLogFileName(const char *name) = 0;
  virtual void* getModuleBase(void *address) = 0;
};

#endif
