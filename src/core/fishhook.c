// Copyright (c) 2013, Facebook, Inc.
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//   * Redistributions of source code must retain the above copyright notice,
//     this list of conditions and the following disclaimer.
//   * Redistributions in binary form must reproduce the above copyright notice,
//     this list of conditions and the following disclaimer in the documentation
//     and/or other materials provided with the distribution.
//   * Neither the name Facebook nor the names of its contributors may be used to
//     endorse or promote products derived from this software without specific
//     prior written permission.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// ---- IOSDecryptHub 扩展 ----
// 在经典 fishhook (间接符号表) 基础上增加:
//   1. __AUTH_CONST 段扫描 (arm64e authenticated GOT)
//   2. arm64e Pointer Authentication 感知 (写入槽 = pacia(strip(replacement),&槽);
//      存原函数 = pacia(strip(旧值),0),只存一次;schema 由 pristine 记录 + 设备实测确认)
//   3. hook 写入失败的能力报告 (dh_health)
// 仍然只改函数指针，不使用 inline hook，不违反架构边界。
// 注: 不走 LC_DYLD_CHAINED_FIXUPS 遍历——fixup 编码只在 dyld bind 前存在,而 fishhook 在 image
//     加载后(bind 完)才跑,运行时读到的是已 bind 的真实指针,当 fixup 解析必是垃圾。故只用间接
//     符号表(LINKEDIT 常驻)定位槽,对 __AUTH_CONST 槽按上面的 PAC schema 签名写入。

#include "fishhook.h"
#include "dh_health.h"

#include <stdio.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/vm_region.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#ifdef __LP64__
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#endif

#ifndef SEG_DATA_CONST
#define SEG_DATA_CONST  "__DATA_CONST"
#endif

#ifndef SEG_AUTH_CONST
#define SEG_AUTH_CONST  "__AUTH_CONST"
#endif

// arm64e PAC helpers — 非 arm64e 编译时退化为 no-op
#if defined(__arm64e__)
#include <ptrauth.h>
#define DH_PAC_STRIP(ptr)       ptrauth_strip((ptr), ptrauth_key_asia)
#define DH_PAC_SIGN_DATA(ptr)   ptrauth_sign_unauthenticated((ptr), ptrauth_key_asia, 0)
#define DH_PAC_SIGN_DATA_D(ptr, div) \
    ptrauth_sign_unauthenticated((ptr), ptrauth_key_asia, (div))
#define DH_IS_ARM64E 1
#else
#define DH_PAC_STRIP(ptr)       (ptr)
#define DH_PAC_SIGN_DATA(ptr)   (ptr)
#define DH_PAC_SIGN_DATA_D(ptr, div) (ptr)
#define DH_IS_ARM64E 0
#endif

struct rebindings_entry {
  struct rebinding *rebindings;
  size_t rebindings_nel;
  struct rebindings_entry *next;
};

static struct rebindings_entry *_rebindings_head;

static int prepend_rebindings(struct rebindings_entry **rebindings_head,
                              struct rebinding rebindings[],
                              size_t nel) {
  struct rebindings_entry *new_entry = (struct rebindings_entry *) malloc(sizeof(struct rebindings_entry));
  if (!new_entry) {
    return -1;
  }
  new_entry->rebindings = (struct rebinding *) malloc(sizeof(struct rebinding) * nel);
  if (!new_entry->rebindings) {
    free(new_entry);
    return -1;
  }
  memcpy(new_entry->rebindings, rebindings, sizeof(struct rebinding) * nel);
  new_entry->rebindings_nel = nel;
  new_entry->next = *rebindings_head;
  *rebindings_head = new_entry;
  return 0;
}

// ---------------------------------------------------------------------------
// 经典路径: 间接符号表 (传统 __DATA/__DATA_CONST GOT)
// ---------------------------------------------------------------------------

// is_auth: 该 section 是否在 __AUTH_CONST(arm64e authenticated GOT)。
// authenticated 槽必须写「用槽地址签过名的指针」,否则调用点 BRAA X16,X17 认证失败 → SIGSEGV
// (这正是源码 arm64e 引擎注入系统进程时崩在 hooked_dladdr 的根因)。schema 由 pristine
// chained-fixup 记录 + 设备实测确认:key IA、地址分散(modifier=槽地址)、disc=0。
//   写入替换 = pacia(strip(replacement), &槽)        配调用点 BRAA X16,X17
//   存原函数 = pacia(strip(旧槽值), 0)               配 hook 内调 orig 的 BLRAAZ
//   存原只存一次(*replaced 仍为 NULL),防多趟重绑把 orig 覆盖成 hook 自身。
// 非 auth 段(__DATA/__DATA_CONST)与非 arm64e 切片:保持裸指针,不签名。
static void perform_rebinding_with_section(struct rebindings_entry *rebindings,
                                           section_t *section,
                                           intptr_t slide,
                                           nlist_t *symtab,
                                           char *strtab,
                                           uint32_t *indirect_symtab,
                                           bool is_auth) {
  uint32_t *indirect_symbol_indices = indirect_symtab + section->reserved1;
  void **indirect_symbol_bindings = (void **)((uintptr_t)slide + section->addr);

  for (uint i = 0; i < section->size / sizeof(void *); i++) {
    uint32_t symtab_index = indirect_symbol_indices[i];
    if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL ||
        symtab_index == (INDIRECT_SYMBOL_LOCAL   | INDIRECT_SYMBOL_ABS)) {
      continue;
    }
    uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
    char *symbol_name = strtab + strtab_offset;
    bool symbol_name_longer_than_1 = symbol_name[0] && symbol_name[1];
    struct rebindings_entry *cur = rebindings;
    while (cur) {
      for (uint j = 0; j < cur->rebindings_nel; j++) {
        if (symbol_name_longer_than_1 &&
            strcmp(&symbol_name[1], cur->rebindings[j].name) == 0) {
          void **slot = &indirect_symbol_bindings[i];
          // 存原函数:只存一次(*replaced 仍为 NULL)且当前槽值不是我们已写的 hook。
          if (cur->rebindings[j].replaced != NULL &&
              *(cur->rebindings[j].replaced) == NULL &&
              *slot != cur->rebindings[j].replacement) {
#if DH_IS_ARM64E
            if (is_auth) {
              *(cur->rebindings[j].replaced) = DH_PAC_SIGN_DATA(DH_PAC_STRIP(*slot));
            } else {
              *(cur->rebindings[j].replaced) = *slot;
            }
#else
            *(cur->rebindings[j].replaced) = *slot;
#endif
          }
          kern_return_t err = vm_protect (mach_task_self (),
              (uintptr_t)indirect_symbol_bindings, section->size, 0,
              VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
          if (err == KERN_SUCCESS) {
#if DH_IS_ARM64E
            if (is_auth) {
              *slot = DH_PAC_SIGN_DATA_D(DH_PAC_STRIP(cur->rebindings[j].replacement),
                                         (uintptr_t)slot);
            } else {
              *slot = cur->rebindings[j].replacement;
            }
#else
            *slot = cur->rebindings[j].replacement;
#endif
          } else {
            dh_health_hook_fail(DH_DIAG_GENERAL, cur->rebindings[j].name);
          }
          goto symbol_loop;
        }
      }
      cur = cur->next;
    }
  symbol_loop:;
  }
}

// ---------------------------------------------------------------------------
// 入口: 对单个 image 执行 rebinding
// ---------------------------------------------------------------------------

static void rebind_symbols_for_image(struct rebindings_entry *rebindings,
                                     const struct mach_header *header,
                                     intptr_t slide) {
  Dl_info info;
  if (dladdr(header, &info) == 0) {
    fprintf(stderr, "[IOSDecryptHub/ERR] dladdr 失败, 跳过 image header=%p (该 image 的 hook 全部未生效)\n",
            (const void *)header);
    return;
  }

  // 说明: 曾有一条 chained-fixups 遍历路径,但它 vm_read 的是运行时「已被 dyld bind 过」的槽,
  // 当成 chained-fixup 编码解析必然是垃圾(真实指针 bit62/63 被 PAC 占 → 误判 bind、垃圾 ordinal
  // → 可能误写),在 fishhook 的运行时(image 加载后)场景从设计上不成立,故删除。真正生效的是下面
  // 基于间接符号表(LINKEDIT,运行时仍在)的经典路径 + __AUTH_CONST 槽的 PAC 签名。

  // 经典路径: 间接符号表 (兼容旧格式 + arm64e authenticated GOT)
  segment_command_t *cur_seg_cmd;
  segment_command_t *linkedit_segment = NULL;
  struct symtab_command* symtab_cmd = NULL;
  struct dysymtab_command* dysymtab_cmd = NULL;

  uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
  for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
    cur_seg_cmd = (segment_command_t *)cur;
    if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
      if (strcmp(cur_seg_cmd->segname, SEG_LINKEDIT) == 0) {
        linkedit_segment = cur_seg_cmd;
      }
    } else if (cur_seg_cmd->cmd == LC_SYMTAB) {
      symtab_cmd = (struct symtab_command*)cur_seg_cmd;
    } else if (cur_seg_cmd->cmd == LC_DYSYMTAB) {
      dysymtab_cmd = (struct dysymtab_command*)cur_seg_cmd;
    }
  }

  if (!symtab_cmd || !dysymtab_cmd || !linkedit_segment ||
      !dysymtab_cmd->nindirectsyms) {
    return;
  }

  // Find base symbol/string table addresses
  uintptr_t linkedit_base = (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
  nlist_t *symtab = (nlist_t *)(linkedit_base + symtab_cmd->symoff);
  char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);

  // Get indirect symbol table (array of uint32_t indices into symbol table)
  uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);

  cur = (uintptr_t)header + sizeof(mach_header_t);
  for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
    cur_seg_cmd = (segment_command_t *)cur;
    if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
      // 扫描 __DATA, __DATA_CONST, __AUTH_CONST 三个段
      if (strcmp(cur_seg_cmd->segname, SEG_DATA) != 0 &&
          strcmp(cur_seg_cmd->segname, SEG_DATA_CONST) != 0 &&
          strcmp(cur_seg_cmd->segname, SEG_AUTH_CONST) != 0) {
        continue;
      }
      for (uint j = 0; j < cur_seg_cmd->nsects; j++) {
        section_t *sect =
          (section_t *)(cur + sizeof(segment_command_t)) + j;
        // authenticated GOT 靠「section 名」判定,不是段名:__auth_got(arm64e 认证 GOT)实际在
        // __DATA_CONST 段(不在 __AUTH_CONST 段),其槽的指针必须 PAC 签名(调用点 braa X16,X17);
        // 同段的 __got 是非认证槽,写裸指针。按段名判会漏掉 __auth_got → 写裸指针 → braa 崩。
        bool is_auth = (strncmp(sect->sectname, "__auth", 6) == 0);
        if ((sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS) {
          perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab, is_auth);
        }
        if ((sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) {
          perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab, is_auth);
        }
      }
    }
  }
}

static void _rebind_symbols_for_image(const struct mach_header *header,
                                      intptr_t slide) {
    rebind_symbols_for_image(_rebindings_head, header, slide);
}

int rebind_symbols_image(void *header,
                         intptr_t slide,
                         struct rebinding rebindings[],
                         size_t rebindings_nel) {
    struct rebindings_entry *rebindings_head = NULL;
    int retval = prepend_rebindings(&rebindings_head, rebindings, rebindings_nel);
    rebind_symbols_for_image(rebindings_head, (const struct mach_header *) header, slide);
    if (rebindings_head) {
      free(rebindings_head->rebindings);
    }
    free(rebindings_head);
    return retval;
}

int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel) {
  int retval = prepend_rebindings(&_rebindings_head, rebindings, rebindings_nel);
  if (retval < 0) {
    return retval;
  }
  // If this was the first call, register callback for image additions (which is also invoked for
  // existing images, otherwise, just run on existing images
  if (!_rebindings_head->next) {
    _dyld_register_func_for_add_image(_rebind_symbols_for_image);
  } else {
    uint32_t c = _dyld_image_count();
    for (uint32_t i = 0; i < c; i++) {
      _rebind_symbols_for_image(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
    }
  }
  return retval;
}
