#include "litehook.h"
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <sys/fcntl.h>
#include <mach/mach.h>
#include <mach/arm/kern_return.h>
#include <mach/port.h>
#include <mach/vm_prot.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <dlfcn.h>
#include <libkern/OSCacheControl.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld_images.h>
#include <sys/syslimits.h>
#include <dispatch/dispatch.h>
#include "dyld_cache_format.h"
#include <ptrauth.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/stat.h>

void litehook_diagnostic_log(const char *format, ...)
{
    // Avoid Foundation/NSUserDefaults while their hooks are being installed.
    int savedErrno = errno;
    const char *home = getenv("LC_HOME_PATH");
    if (!home || !home[0]) {
        errno = savedErrno;
        return;
    }
    char path[PATH_MAX];
    int length = snprintf(path, sizeof(path), "%s/Documents", home);
    if (length < 0 || length >= sizeof(path)) {
        errno = savedErrno;
        return;
    }
    mkdir(path, 0700);
    length = snprintf(path, sizeof(path), "%s/Documents/LC-NSUserDefaults-diagnostics.log", home);
    if (length < 0 || length >= sizeof(path)) {
        errno = savedErrno;
        return;
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) {
        fprintf(stderr, "litehook diagnostics: open failed: %s (errno=%d)\n", path, errno);
        errno = savedErrno;
        return;
    }
    struct timeval now;
    gettimeofday(&now, NULL);
    uint64_t threadID = 0;
    pthread_threadid_np(NULL, &threadID);
    char line[2048];
    int prefix = snprintf(line, sizeof(line), "[%lld.%06d pid=%d tid=%llu] ",
                          (long long)now.tv_sec, (int)now.tv_usec, getpid(), (unsigned long long)threadID);
    va_list args;
    va_start(args, format);
    vsnprintf(line + prefix, sizeof(line) - prefix, format, args);
    va_end(args);
    size_t size = strnlen(line, sizeof(line) - 2);
    line[size++] = '\n';
    size_t written = 0;
    while (written < size) {
        ssize_t count = write(fd, line + written, size - written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) break;
        written += count;
    }
    fsync(fd); // Preserve the last checkpoint if the next operation crashes.
    close(fd);
    errno = savedErrno;
}

#if __arm64__
#define _COMM_PAGE_START_ADDRESS (0x0000000FFFFFC000ULL)
#define _COMM_PAGE_TPRO_WRITE_ENABLE (_COMM_PAGE_START_ADDRESS + 0x0D0)
#define _COMM_PAGE_TPRO_WRITE_DISABLE (_COMM_PAGE_START_ADDRESS + 0x0D8)

bool os_tpro_is_supported(void)
{
	if (*(uint64_t*)_COMM_PAGE_TPRO_WRITE_ENABLE) {
		return true;
	}
	return false;
}

__attribute__((naked)) bool os_thread_self_tpro_is_writeable(void)
{
	__asm__ __volatile__ (
		"mrs             x0, s3_6_c15_c1_5\n"
		"ubfx            x0, x0, #0x24, #1;\n"
		"ret\n"
	);
}

void os_thread_self_restrict_tpro_to_rw(void)
{
	__asm__ __volatile__ (
		"mov x0, %0\n"
		"ldr x0, [x0]\n"
		"msr s3_6_c15_c1_5, x0\n"
		"isb sy\n"
		:: "r" (_COMM_PAGE_TPRO_WRITE_ENABLE)
		: "memory", "x0"
	);
	return;
}

void os_thread_self_restrict_tpro_to_ro(void)
{
	__asm__ __volatile__ (
		"mov x0, %0\n"
		"ldr x0, [x0]\n"
		"msr s3_6_c15_c1_5, x0\n"
		"isb sy\n"
		:: "r" (_COMM_PAGE_TPRO_WRITE_DISABLE)
		: "memory", "x0"
	);
	return;
}
#endif

size_t _lth_fstrlen(FILE *f)
{
	size_t sz = 0;
	uint32_t prev = ftell(f);
	while (true) {
		char c = 0;
		if (fread(&c, sizeof(c), 1, f) != 1) break;
		if (c == 0) break;
		sz++;
	}
	fseek(f, prev, SEEK_SET);
	return sz;
}

uint32_t _lth_arm64_gen_movk(uint8_t x, uint16_t val, uint16_t lsl)
{
	uint32_t base = 0b11110010100000000000000000000000;

	uint32_t hw = 0;
	if (lsl == 16) {
		hw = 0b01 << 21;
	}
	else if (lsl == 32) {
		hw = 0b10 << 21;
	}
	else if (lsl == 48) {
		hw = 0b11 << 21;
	}

	uint32_t imm16 = (uint32_t)val << 5;
	uint32_t rd = x & 0x1F;

	return base | hw | imm16 | rd;
}

uint32_t _lth_arm64_gen_br(uint8_t x)
{
	uint32_t base = 0b11010110000111110000000000000000;
	uint32_t rn = ((uint32_t)x & 0x1F) << 5;
	return base | rn;
}

__attribute__((noinline, naked)) volatile kern_return_t litehook_vm_protect(mach_port_name_t target, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection)
{
#ifdef __arm64__
	__asm("mov x16, #-14");
	__asm("svc 0x80");
	__asm("ret");
#else
	// broken....
	__asm("mov r12, #-14");
	__asm("svc 0x80");
	__asm("bx lr");
#endif
}

kern_return_t litehook_unprotect(vm_address_t addr, vm_size_t size)
{
	return litehook_vm_protect(mach_task_self(), addr, size, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
}

kern_return_t litehook_protect(vm_address_t addr, vm_size_t size)
{
	return litehook_vm_protect(mach_task_self(), addr, size, false, VM_PROT_READ | VM_PROT_EXECUTE);
}

kern_return_t litehook_hook_function(void *source, void *target)
{
	kern_return_t kr = KERN_SUCCESS;

	uint32_t *toHook = (uint32_t*)ptrauth_strip(source, ptrauth_key_function_pointer);
	uint64_t targetAddr = (uint64_t)ptrauth_strip(target, ptrauth_key_function_pointer);

	kr = litehook_unprotect((vm_address_t)toHook, 5*4);
	if (kr != KERN_SUCCESS) return kr;

	toHook[0] = _lth_arm64_gen_movk(16, targetAddr >>  0,  0);
	toHook[1] = _lth_arm64_gen_movk(16, targetAddr >> 16, 16);
	toHook[2] = _lth_arm64_gen_movk(16, targetAddr >> 32, 32);
	toHook[3] = _lth_arm64_gen_movk(16, targetAddr >> 48, 48);
	toHook[4] = _lth_arm64_gen_br(16);
	uint32_t hookSize = 5 * sizeof(uint32_t);

	kr = litehook_protect((vm_address_t)toHook, hookSize);
	if (kr != KERN_SUCCESS) return kr;

	sys_icache_invalidate(toHook, hookSize);

	return KERN_SUCCESS;
}

const char *litehook_locate_dsc(void)
{
	static char dscPath[PATH_MAX] = {};
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		char *dyldSharedRegion   = getenv("DYLD_SHARED_REGION");
		char *dyldSharedCacheDir = getenv("DYLD_SHARED_CACHE_DIR");
		if (dyldSharedRegion && dyldSharedCacheDir && !strcmp(dyldSharedRegion, "private")) {
			// If the local process uses a custom private dsc, use that as the path
			strlcpy(dscPath, dyldSharedCacheDir, PATH_MAX);
			strlcat(dscPath, "/dyld_shared_cache", PATH_MAX);
		}
		else if (!access("/private/preboot/Cryptexes/OS/System/Library/Caches/com.apple.dyld", F_OK)) /* iOS >=16 */ {
			strlcpy(dscPath, "/private/preboot/Cryptexes/OS/System/Library/Caches/com.apple.dyld/dyld_shared_cache", PATH_MAX);
		}
		else if (!access("/System/Library/Caches/com.apple.dyld", F_OK)) /* iOS <=15 */ {
			strlcpy(dscPath, "/System/Library/Caches/com.apple.dyld/dyld_shared_cache", PATH_MAX);
		}

		const char *suffixCandidates[] = {
			"_arm64e_x1",
			"_arm64e",
			"_arm64",
			"_armv7s",
			"_armv7",
		};
		char *rChar = &dscPath[strlen(dscPath)];
		for (int i = 0; i < sizeof(suffixCandidates)/sizeof(*suffixCandidates); i++) {
			*rChar = '\0';
			strlcat(dscPath, suffixCandidates[i], PATH_MAX);
			if (!access(dscPath, F_OK)) {
				break;
			}
		}
		if (access(dscPath, F_OK) != 0) strlcpy(dscPath, "", PATH_MAX);
	});
	return (const char *)dscPath;
}

uintptr_t litehook_get_dsc_slide(void)
{
	static uintptr_t slide = 0;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		task_dyld_info_data_t dyldInfo;
		uint32_t count = TASK_DYLD_INFO_COUNT;
		task_info(mach_task_self_, TASK_DYLD_INFO, (task_info_t)&dyldInfo, &count);
		struct dyld_all_image_infos *infos = (struct dyld_all_image_infos *)dyldInfo.all_image_info_addr;
		slide = infos->sharedCacheSlide;
	});
	return slide;
}

void *_litehook_sign_if_executable(void *ptr)
{
	vm_address_t region = (vm_address_t)ptr;
	vm_size_t region_len = 0;
	struct vm_region_submap_short_info_64 info;
	mach_msg_type_number_t info_count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
	natural_t max_depth = 99999;
	kern_return_t kr = vm_region_recurse_64(mach_task_self(), &region, &region_len, &max_depth, (vm_region_recurse_info_t)&info, &info_count);
	if (info.protection & PROT_EXEC) {
		return ptrauth_sign_unauthenticated(ptr, ptrauth_key_function_pointer, 0);
	}
	return ptr;
}

void *litehook_find_symbol(const mach_header_u *header, const char *symbolName)
{
	struct symtab_command *symtabCommand = NULL;
	segment_command_u *linkeditSegCommand = NULL;

	uint32_t slide = -1;

	uint32_t off = 0;
	for (uint32_t i = 0; i < header->ncmds && off < header->sizeofcmds; i++) {
		struct load_command *lc = (struct load_command *)((uintptr_t)header + sizeof(mach_header_u) + off);

		if (lc->cmd == LC_SYMTAB) {
			symtabCommand = (struct symtab_command *)lc;
		}
		else if (lc->cmd == LC_SEGMENT_U) {
			segment_command_u *segCmd = (segment_command_u *)lc;
			if (slide == -1) {
				slide = (uintptr_t)header - segCmd->vmaddr;
			}
			if (!strncmp(segCmd->segname, "__LINKEDIT", sizeof(segCmd->segname))) {
				linkeditSegCommand = segCmd;
			}
		}

		if (symtabCommand && linkeditSegCommand) break;

		off += lc->cmdsize;
	}

	if (!symtabCommand || !linkeditSegCommand) return NULL;

	uint8_t *linkedit = (uint8_t *)((uintptr_t)header + linkeditSegCommand->vmaddr);

	nlist_u *syms = (nlist_u *)(linkedit + (symtabCommand->symoff - linkeditSegCommand->fileoff));
	char *strtbl = (char *)(linkedit + (symtabCommand->stroff - linkeditSegCommand->fileoff));
	size_t strtblSize = symtabCommand->strsize;

	for (uint32_t i = 0; i < symtabCommand->nsyms; i++) {
		nlist_u *symEntry = &syms[i];

		uint32_t stroff = symEntry->n_un.n_strx;
		if (stroff >= strtblSize || off == 0) {
			continue;
		}

		if ((symEntry->n_type & N_TYPE) != N_SECT) {
			continue;
		}

		const char* curSymbolName = &strtbl[stroff];
		if (curSymbolName[0] == '\x00') {
			continue;
		}

		if (!strcmp(curSymbolName, symbolName)) {
			return _litehook_sign_if_executable((void *)((uintptr_t)header + symEntry->n_value));
		}
	}

	return NULL;
}

void *litehook_find_symbol_file(const mach_header_u *header, const char *symbolName)
{
    struct symtab_command *symtabCommand = NULL;

    uint32_t slide = -1;

    uint32_t off = 0;
    for (uint32_t i = 0; i < header->ncmds && off < header->sizeofcmds; i++) {
        struct load_command *lc = (struct load_command *)((uintptr_t)header + sizeof(mach_header_u) + off);

        if (lc->cmd == LC_SYMTAB) {
            symtabCommand = (struct symtab_command *)lc;
        }
        else if (lc->cmd == LC_SEGMENT_U) {
            segment_command_u *segCmd = (segment_command_u *)lc;
            if (slide == -1) {
                slide = (uintptr_t)header - segCmd->vmaddr;
            }
        }

        if (symtabCommand) break;

        off += lc->cmdsize;
    }

    if (!symtabCommand) return NULL;

    nlist_u *syms = (nlist_u *)((void*)header + symtabCommand->symoff);
    char *strtbl = (char *)((void*)header + symtabCommand->stroff);
    size_t strtblSize = symtabCommand->strsize;

    for (uint32_t i = 0; i < symtabCommand->nsyms; i++) {
        nlist_u *symEntry = &syms[i];

        uint32_t stroff = symEntry->n_un.n_strx;
        if (stroff >= strtblSize || off == 0) {
            continue;
        }

        if ((symEntry->n_type & N_TYPE) != N_SECT) {
            continue;
        }

        const char* curSymbolName = &strtbl[stroff];
        if (curSymbolName[0] == '\x00') {
            continue;
        }

        if (!strcmp(curSymbolName, symbolName)) {
            return _litehook_sign_if_executable((void *)((uintptr_t)header + symEntry->n_value));
        }
    }

    return NULL;
}

void *litehook_find_dsc_symbol(const char *imagePath, const char *symbolName)
{
    // Include the requested symbol on every line so concurrent lookups can be separated.
#define DSC_LOG(fmt, ...) litehook_diagnostic_log("DSC [%s] " fmt, symbolName, ##__VA_ARGS__)
#define DSC_SEEK(file, offset) do { \
    if (fseek(file, offset, SEEK_SET) != 0) { \
        DSC_LOG("FAIL line=%d fseek(%s) offset=%llu errno=%d", __LINE__, #file, (unsigned long long)(offset), errno); \
        goto end; \
    } \
} while (0)
#define DSC_READ(value, size, file) do { \
    long position = ftell(file); \
    if (fread(value, size, 1, file) != 1) { \
        DSC_LOG("FAIL line=%d fread(%s) offset=%ld size=%zu eof=%d error=%d errno=%d", __LINE__, #value, position, (size_t)(size), feof(file), ferror(file), errno); \
        goto end; \
    } \
} while (0)
    DSC_LOG("begin image=%s; locating DSC", imagePath);
    const char *mainDSCPath = litehook_locate_dsc();
    DSC_LOG("locate DSC returned path=%s", mainDSCPath ?: "(null)");
    if (!mainDSCPath || !strlen(mainDSCPath)) {
        DSC_LOG("return NULL: no DSC path");
        return NULL;
    }

    char symbolDSCPath[PATH_MAX];
    strcpy(symbolDSCPath, mainDSCPath);
    strcat(symbolDSCPath, ".symbols");

    void *symbol = NULL;

    FILE *symbolDSC = NULL;
    DSC_LOG("opening main cache: %s", mainDSCPath);
    FILE *mainDSC = fopen(mainDSCPath, "rb");
    if (!mainDSC) {
        DSC_LOG("FAIL fopen main cache errno=%d (%s)", errno, strerror(errno));
        goto end;
    }
    DSC_LOG("opening symbol cache: %s", symbolDSCPath);
    symbolDSC = fopen(symbolDSCPath, "rb");
    if (!symbolDSC) {
        DSC_LOG("fopen .symbols failed errno=%d (%s); falling back to main cache", errno, strerror(errno));
        symbolDSC = mainDSC;
    }

    int imageIndex = -1;

    struct dyld_cache_header mainHeader;
    DSC_READ(&mainHeader, sizeof(mainHeader), mainDSC);

    DSC_LOG("main header magic=%.16s mappingOffset=%u imagesOffset=%u imagesCount=%u localSymbolsOffset=%llu localSymbolsSize=%llu", mainHeader.magic, mainHeader.mappingOffset, mainHeader.imagesOffset, mainHeader.imagesCount, (unsigned long long)mainHeader.localSymbolsOffset, (unsigned long long)mainHeader.localSymbolsSize);
    DSC_LOG("scanning image table");
    for (int i = 0; i < mainHeader.imagesCount; i++) {
        struct dyld_cache_image_info imageInfo;
        DSC_SEEK(mainDSC, mainHeader.imagesOffset + sizeof(imageInfo) * i);
        DSC_READ(&imageInfo, sizeof(imageInfo), mainDSC);

        char path[PATH_MAX];
        DSC_SEEK(mainDSC, imageInfo.pathFileOffset);
        DSC_READ(path, PATH_MAX, mainDSC);

        if (!memchr(path, 0, sizeof(path))) {
            DSC_LOG("FAIL image path is not terminated index=%d pathOffset=%u", i, imageInfo.pathFileOffset);
            goto end;
        }
        if (!strcmp(path, imagePath)) {
            DSC_LOG("matched image index=%d pathOffset=%u address=0x%llx", i, imageInfo.pathFileOffset, (unsigned long long)imageInfo.address);
            imageIndex = i;
            break;
        }
    }

    DSC_LOG("image scan complete index=%d; reading symbol header at offset=%ld fallback=%d", imageIndex, ftell(symbolDSC), symbolDSC == mainDSC);
    struct dyld_cache_header symbolHeader;
    DSC_READ(&symbolHeader, sizeof(symbolHeader), symbolDSC);

    DSC_LOG("symbol header magic=%.16s localSymbolsOffset=%llu localSymbolsSize=%llu", symbolHeader.magic, (unsigned long long)symbolHeader.localSymbolsOffset, (unsigned long long)symbolHeader.localSymbolsSize);
    struct dyld_cache_local_symbols_info symbolInfo;
    DSC_SEEK(symbolDSC, symbolHeader.localSymbolsOffset);
    DSC_READ(&symbolInfo, sizeof(symbolInfo), symbolDSC);

    DSC_LOG("local symbols nlistOffset=%u nlistCount=%u stringsOffset=%u stringsSize=%u entriesOffset=%u entriesCount=%u imageIndex=%d", symbolInfo.nlistOffset, symbolInfo.nlistCount, symbolInfo.stringsOffset, symbolInfo.stringsSize, symbolInfo.entriesOffset, symbolInfo.entriesCount, imageIndex);
    if (imageIndex >= symbolInfo.entriesCount) {
        DSC_LOG("return NULL: image index outside local symbol entries (or image not found)");
        goto end;
    }

    struct dyld_cache_local_symbols_entry_64 entry;

    if (mainHeader.mappingOffset >= offsetof(struct dyld_cache_header, symbolFileUUID)) {
        DSC_LOG("reading 64-bit local symbol entry");
        // New shared cache, dyld_cache_local_symbols_entry_64
        DSC_SEEK(symbolDSC, symbolHeader.localSymbolsOffset + symbolInfo.entriesOffset + (sizeof(entry) * imageIndex));
        DSC_READ(&entry, sizeof(entry), symbolDSC);
    }
    else {
        DSC_LOG("reading legacy local symbol entry");
        // Old shared cache, dyld_cache_local_symbols_entry
        struct dyld_cache_local_symbols_entry entryOld;
        DSC_SEEK(symbolDSC, symbolHeader.localSymbolsOffset + symbolInfo.entriesOffset + (sizeof(entryOld) * imageIndex));
        DSC_READ(&entryOld, sizeof(entryOld), symbolDSC);

        // Convert dyld_cache_local_symbols_entry to dyld_cache_local_symbols_entry_64
        entry = (struct dyld_cache_local_symbols_entry_64) {
            .dylibOffset = entryOld.dylibOffset,
            .nlistStartIndex = entryOld.nlistStartIndex,
            .nlistCount = entryOld.nlistCount,
        };
    }

    DSC_LOG("entry dylibOffset=0x%llx nlistStartIndex=%u nlistCount=%u", (unsigned long long)entry.dylibOffset, entry.nlistStartIndex, entry.nlistCount);
    if ((entry.nlistStartIndex + entry.nlistCount) > symbolInfo.nlistCount) {
        DSC_LOG("return NULL: entry symbol range exceeds nlistCount");
        goto end;
    }
    DSC_LOG("scanning symbol table");

    for (uint32_t i = entry.nlistStartIndex; i < entry.nlistStartIndex + entry.nlistCount; i++) {
        if ((i - entry.nlistStartIndex) % 1024 == 0) DSC_LOG("symbol scan progress index=%u", i);
        struct nlist_64 n;
        DSC_SEEK(symbolDSC, symbolHeader.localSymbolsOffset + symbolInfo.nlistOffset + (sizeof(n) * i));
        DSC_READ(&n, sizeof(n), symbolDSC);

        DSC_SEEK(symbolDSC, symbolHeader.localSymbolsOffset + symbolInfo.stringsOffset + n.n_un.n_strx);
        size_t len = _lth_fstrlen(symbolDSC);
        if (len > 4096) DSC_LOG("large symbol name before stack allocation index=%u strx=%u len=%zu", i, n.n_un.n_strx, len);
        char curSymbolName[len+1];
        DSC_READ(curSymbolName, len+1, symbolDSC);
        if (!strcmp(curSymbolName, symbolName)) {
            DSC_LOG("matched symbol index=%u strx=%u value=0x%llx; obtaining DSC slide", i, n.n_un.n_strx, (unsigned long long)n.n_value);
            uintptr_t slide = litehook_get_dsc_slide();
            DSC_LOG("slide=0x%llx candidate=%p; before sign_if_executable", (unsigned long long)slide, (void *)(slide + n.n_value));
            symbol = _litehook_sign_if_executable((void *)(slide + n.n_value));
            DSC_LOG("sign_if_executable returned %p", symbol);
        }
    }

    DSC_LOG("symbol scan complete result=%p", symbol);
end:
    DSC_LOG("cleanup result=%p mainDSC=%p symbolDSC=%p", symbol, mainDSC, symbolDSC);
    if (mainDSC) {
        if (symbolDSC && symbolDSC != mainDSC) {
            fclose(symbolDSC);
        }
        fclose(mainDSC);
    }

    DSC_LOG("return %p%s", symbol, symbol ? "" : " (no symbol found / failure above)");
#undef DSC_READ
#undef DSC_SEEK
#undef DSC_LOG
    return symbol;
}

void _litehook_rebind_symbol_in_section(const mach_header_u *targetHeader, section_u *section, void *replacee, void *replacement)
{
	char segname[sizeof(section->segname)+1];
	strlcpy(segname, section->segname, sizeof(segname));
	char sectname[sizeof(section->sectname)+1];
	strlcpy(sectname, section->sectname, sizeof(sectname));

	unsigned long sectionSize = 0;
	uint8_t *sectionStart = getsectiondata(targetHeader, segname, sectname, &sectionSize);

	bool auth = !strcmp(sectname, "__auth_got");

	void **symbolPointers = (void **)sectionStart;
	replacee = ptrauth_strip(ptrauth_auth_function(replacee, ptrauth_key_function_pointer, 0), ptrauth_key_function_pointer);

	for (uint32_t i = 0; i < (sectionSize / sizeof(void *)); i++) {
		void *symbolPointer = symbolPointers[i];
		if (!symbolPointer) continue;

		if (auth) symbolPointer = ptrauth_strip(ptrauth_auth_function(symbolPointers[i], ptrauth_key_function_pointer, &symbolPointers[i]), ptrauth_key_function_pointer);

		if (symbolPointer == replacee) {
#if __arm64__
			bool needsTPRORevert = false;
			if (os_tpro_is_supported()) {
				if (!os_thread_self_tpro_is_writeable()) {
					os_thread_self_restrict_tpro_to_rw();
					needsTPRORevert = true;
				}
			}
#endif
			litehook_unprotect((vm_address_t)&symbolPointers[i], sizeof(void *));
			if (auth) { 
				symbolPointers[i] = ptrauth_auth_and_resign(replacement, ptrauth_key_function_pointer, 0, ptrauth_key_process_independent_code, &symbolPointers[i]);
			}
			else {
				symbolPointers[i] = ptrauth_strip(replacement, ptrauth_key_function_pointer);
			}
#if __arm64__
			if (needsTPRORevert) {
				os_thread_self_restrict_tpro_to_ro();
			}
#endif
		}
	}
}

uint32_t gRebindCount = 0;
global_rebind *gRebinds = NULL;

void _litehook_apply_global_rebind(const mach_header_u *mh, global_rebind *rebind)
{
	if (mh != rebind->sourceHeader) {
		bool filterAllowed = true;
		if (rebind->exceptionFilter) filterAllowed = rebind->exceptionFilter(mh);
		if (filterAllowed) {
			litehook_rebind_symbol(mh, rebind->replacee, rebind->replacement, NULL);
		}
	}
}

void _litehook_apply_global_rebinds(const mach_header_u *mh, intptr_t vmaddr_slide)
{
	if (!gRebinds || gRebindCount == 0) return;

	for (uint32_t i = 0; i < gRebindCount; i++) {
		// Apply all existing rebinds for newly loaded image
		_litehook_apply_global_rebind(mh, &gRebinds[i]);
	}
}

void litehook_rebind_symbol(const mach_header_u *targetHeader, void *replacee, void *replacement, bool (*exceptionFilter)(const mach_header_u *header))
{
	if (targetHeader == LITEHOOK_REBIND_GLOBAL) {
		if (!replacee || !replacement) return;

		// We need the mach_header in which the replacement function lives, since we want to exclude it from the rebind
		Dl_info replacementInfo = {};
		if (dladdr(replacement, &replacementInfo) == 0) return;
		if (replacementInfo.dli_fname == NULL) return;
		const mach_header_u *sourceHeader = NULL;
		for (unsigned i = 0; i < _dyld_image_count(); i++) {
			if (!strcmp(_dyld_get_image_name(i), replacementInfo.dli_fname)) {
				sourceHeader = (const mach_header_u *)_dyld_get_image_header(i);
				break;
			}
		}
		if (!sourceHeader) return;

		if (!gRebinds) {
			_dyld_register_func_for_add_image((void (*)(const struct mach_header *, intptr_t))_litehook_apply_global_rebinds);
		}

		gRebinds = realloc(gRebinds, sizeof(global_rebind) * ++gRebindCount);

		global_rebind *rebind = &gRebinds[gRebindCount-1];
		rebind->sourceHeader = sourceHeader;
		rebind->replacee = replacee;
		rebind->replacement = replacement;
		rebind->exceptionFilter = exceptionFilter;

		for (uint32_t i = 0; i < _dyld_image_count(); i++) {
			const mach_header_u *header = (const mach_header_u *)_dyld_get_image_header(i);
			// Apply new rebind for all already loaded images
			_litehook_apply_global_rebind(header, rebind);
		}
	}
	else {
		struct load_command *lcp = (void *)((uintptr_t)targetHeader + sizeof(mach_header_u));
		for(int i = 0; i < targetHeader->ncmds; i++) {
			if (lcp->cmd == LC_SEGMENT_U) {
				segment_command_u *segCmd = (segment_command_u *)lcp;
				if (!strncmp(segCmd->segname, "__AUTH_CONST", sizeof(segCmd->segname)) ||
					!strncmp(segCmd->segname, "__DATA_CONST", sizeof(segCmd->segname)) ||
					!strncmp(segCmd->segname, "__DATA", sizeof(segCmd->segname))) {
					section_u *sections = (void *)((uintptr_t)lcp + sizeof(segment_command_u));
					for (int j = 0; j < segCmd->nsects; j++) {
						if ((sections[j].flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS || 
							(sections[j].flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) {
							_litehook_rebind_symbol_in_section(targetHeader, &sections[j], replacee, replacement);
						}
					}
				}
			}
			lcp = (void *)((uintptr_t)lcp + lcp->cmdsize);
		}
	}
}
