#include <idaldr.h>
#include <typeinf.hpp>

#include <elf/elfbase.h>
#include <elf/elfr_ppc.h>

extern "C" {
#define TINFL_HEADER_FILE_ONLY
#include "tinfl.c"
}

// elf_ident_t.osabi
#define ELFOSABI_CAFE      0xCA

// elf_ident_t.abiversion
#define ELFABIVERSION_CAFE 0xFE

// Elf32_Ehdr.e_type
#define ET_CAFE_RPL        0xfe01

// Elf32_Shdr.sh_flags
#define SHF_RPL_DEFLATED   0x08000000

// Elf32_Shdr.sh_type
#define SHT_RPL_EXPORTS    0x80000001
#define SHT_RPL_IMPORTS    0x80000002
#define SHT_RPL_CRCS       0x80000003
#define SHT_RPL_FILEINFO   0x80000004

// Export SHT_RPL_EXPORTS name TLS flag
#define EXN_RPL_TLS        0x80000000

// GHS custom relocation types
#define R_PPC_GHS_REL16_HA 251
#define R_PPC_GHS_REL16_HI 252
#define R_PPC_GHS_REL16_LO 253

struct LoadedSection
{
   Elf32_Shdr shdr;
   qvector<char> data;

   // Only set if shdr.sh_type = SHT_RPL_IMPORTS
   netnode importNode;
};

struct LoadedFile
{
   Elf32_Ehdr ehdr;
   qvector<LoadedSection> sections;

   ea_t importsBaseAddress;
   segment_t externSegm;
};

static bool
loadElfHeader(linput_t *li,
              Elf32_Ehdr &ehdr,
              qstring &errorMsg)
{
   if (qlread(li, &ehdr.e_ident, sizeof(elf_ident_t)) != sizeof(elf_ident_t)) {
      errorMsg.sprnt("Failed to read ehdr.e_ident");
      return false;
   }

#if __MF__
   if (!ehdr.e_ident.magic == ELF_MAGIC) {
#else
   if (!ehdr.e_ident.magic == swap32(ELF_MAGIC)) {
#endif
      errorMsg.sprnt("Unexpected ehdr.e_ident.magic 0x%X, expected 0x%x",
                     ehdr.e_ident.magic, ELF_MAGIC);
      return false;
   }

   if (ehdr.e_ident.elf_class != ELFCLASS32) {
      errorMsg.sprnt("Unexpected ehdr.e_ident.elf_class 0x%X, expected 0x%X",
                     ehdr.e_ident.elf_class, ELFCLASS32);
      return false;
   }

   if (ehdr.e_ident.bytesex != ELFDATA2MSB) {
      errorMsg.sprnt("Unexpected ehdr.e_ident.bytesex 0x%X, expected 0x%X",
                     ehdr.e_ident.bytesex, ELFDATA2MSB);
      return false;
   }

   if (ehdr.e_ident.version != EV_CURRENT) {
      errorMsg.sprnt("Unexpected ehdr.e_ident.version 0x%X, expected 0x%X",
                     ehdr.e_ident.version, EV_CURRENT);
      return false;
   }

   if (ehdr.e_ident.osabi != ELFOSABI_CAFE) {
      errorMsg.sprnt("Unexpected ehdr.e_ident.osabi 0x%X, expected 0x%X",
                     ehdr.e_ident.osabi, ELFOSABI_CAFE);
      return false;
   }

   if (ehdr.e_ident.abiversion != ELFABIVERSION_CAFE) {
      errorMsg.sprnt("Unexpected ehdr.e_ident.abiversion 0x%X, expected 0x%X",
                     ehdr.e_ident.abiversion, ELFABIVERSION_CAFE);
      return false;
   }

   if (lread2bytes(li, &ehdr.e_type, true) ||
       ehdr.e_type != ET_CAFE_RPL) {
      errorMsg.sprnt("Unexpected ehdr.e_type 0x%X, expected 0x%X",
                     ehdr.e_type, ET_CAFE_RPL);
      return false;
   }

   if (lread2bytes(li, &ehdr.e_machine, true) ||
       ehdr.e_machine != EM_PPC) {
      errorMsg.sprnt("Unexpected ehdr.e_machine 0x%X, expected 0x%X",
                     ehdr.e_machine, EM_PPC);
      return false;
   }

   if (lread4bytes(li, &ehdr.e_version, true) ||
       ehdr.e_version != EV_CURRENT) {
      errorMsg.sprnt("Unexpected ehdr.e_version 0x%X, expected 0x%X",
                     ehdr.e_version, EV_CURRENT);
      return false;
   }

   if (lread4bytes(li, &ehdr.e_entry, true)) {
      errorMsg.sprnt("Failed to read ehdr.e_entry");
      return false;
   }

   if (lread4bytes(li, &ehdr.e_phoff, true)) {
      errorMsg.sprnt("Failed to read ehdr.e_phoff");
      return false;
   }

   if (lread4bytes(li, &ehdr.e_shoff, true)) {
      errorMsg.sprnt("Failed to read ehdr.e_shoff");
      return false;
   }

   if (lread4bytes(li, &ehdr.e_flags, true)) {
      errorMsg.sprnt("Failed to read ehdr.e_flags");
      return false;
   }

   if (lread2bytes(li, &ehdr.e_ehsize, true) ||
       ehdr.e_ehsize != sizeof(Elf32_Ehdr)) {
      errorMsg.sprnt("Unexpected ehdr.e_ehsize 0x%X, expected 0x%X",
                     ehdr.e_ehsize, sizeof(Elf32_Ehdr));
      return false;
   }

   if (lread2bytes(li, &ehdr.e_phentsize, true) ||
       (ehdr.e_phentsize != 0 &&
        ehdr.e_phentsize != sizeof(Elf32_Phdr))) {
      errorMsg.sprnt("Unexpected ehdr.e_phentsize 0x%X, expected 0x%X or 0",
                     ehdr.e_phentsize, sizeof(Elf32_Phdr));
      return false;
   }

   if (lread2bytes(li, &ehdr.e_phnum, true)) {
      errorMsg.sprnt("Failed to read ehdr.e_phnum");
      return false;
   }

   if (lread2bytes(li, &ehdr.e_shentsize, true) ||
       ehdr.e_shentsize != sizeof(Elf32_Shdr)) {
      errorMsg.sprnt("Unexpected ehdr.e_shentsize 0x%X, expected 0x%X",
                     ehdr.e_shentsize, sizeof(Elf32_Shdr));
      return false;
   }

   if (lread2bytes(li, &ehdr.e_shnum, true)) {
      errorMsg.sprnt("Failed to read ehdr.e_shnum");
      return false;
   }

   if (lread2bytes(li, &ehdr.e_shstrndx, true)) {
      errorMsg.sprnt("Failed to read ehdr.e_shstrndx");
      return false;

   }

   if (ehdr.e_shstrndx > ehdr.e_shnum) {
      errorMsg.sprnt("Unexpected ehdr.e_shstrndx 0x%X > ehdr.e_shnum 0x%X",
                     ehdr.e_shentsize, ehdr.e_shnum);
      return false;
   }

   return true;
}

static bool
loadSectionHeader(linput_t *li,
                  Elf32_Shdr &shdr)
{
#define _safe(x) if ((x)) { return false; }
   _safe(lread4bytes(li, &shdr.sh_name, true));
   _safe(lread4bytes(li, &shdr.sh_type, true));
   _safe(lread4bytes(li, &shdr.sh_flags, true));
   _safe(lread4bytes(li, &shdr.sh_addr, true));
   _safe(lread4bytes(li, &shdr.sh_offset, true));
   _safe(lread4bytes(li, &shdr.sh_size, true));
   _safe(lread4bytes(li, &shdr.sh_link, true));
   _safe(lread4bytes(li, &shdr.sh_info, true));
   _safe(lread4bytes(li, &shdr.sh_addralign, true));
   _safe(lread4bytes(li, &shdr.sh_entsize, true));
#undef _safe
   return true;
}

static bool
loadSectionData(linput_t *li,
                const Elf32_Shdr &shdr,
                qvector<char> &data)
{
   qlseek(li, shdr.sh_offset);

   if (shdr.sh_flags & SHF_RPL_DEFLATED) {
      // Read deflated size
      auto deflatedSize = uint32 { 0 };
      lread4bytes(li, &deflatedSize, true);
      data.resize(deflatedSize);

      // Read inflated data
      auto inflatedData = qvector<char> { };
      inflatedData.resize(shdr.sh_size - 4);
      qlread(li, &inflatedData[0], inflatedData.size());

      auto decompressedSize =
         tinfl_decompress_mem_to_mem(&data[0], data.size(),
                                     &inflatedData[0], inflatedData.size(),
                                     TINFL_FLAG_PARSE_ZLIB_HEADER);

      if (decompressedSize != deflatedSize) {
         msg("Unexpected decompressedSize 0x%X, expected 0x%X\n",
             decompressedSize,
             deflatedSize);
         data.resize(decompressedSize);
      }
   } else {
      data.resize(shdr.sh_size);
      qlread(li, &data[0], data.size());
   }

   return true;
}

static void
loadSections(linput_t *li,
             LoadedFile &file)
{
   range_t importRange;
   importRange.start_ea = 0xFFFFFFFF;
   importRange.end_ea = 0;

   file.externSegm.start_ea = 0;
   file.externSegm.end_ea = 0;

   file.sections.resize(file.ehdr.e_shnum);

   // Load sections
   for (auto i = 0u; i < file.ehdr.e_shnum; ++i) {
      auto &section = file.sections[i];
      qlseek(li, file.ehdr.e_shoff + file.ehdr.e_shentsize * i);
      if (!loadSectionHeader(li, section.shdr)) {
         loader_failure("Failed to load section %u header", i);
      }

      if (section.shdr.sh_type == SHT_NOBITS || section.shdr.sh_size == 0) {
         continue;
      }

      if (!loadSectionData(li, section.shdr, section.data)) {
         loader_failure("Failed to load section %u data", i);
      }

      // Create an import node for an import section
      if (section.shdr.sh_type == SHT_RPL_IMPORTS) {
         auto section_start = section.shdr.sh_addr;
         auto section_end = section_start + section.data.size();

         if (section_start < importRange.start_ea) {
            importRange.start_ea = section_start;
         }

         if (section_end > importRange.end_ea) {
            importRange.end_ea = static_cast<ea_t>(section_end);
         }

         section.importNode.create();
      }

      // Find the last code section to place the import section after
      if (section.shdr.sh_type == SHT_PROGBITS &&
         (section.shdr.sh_flags & SHF_EXECINSTR)) {
         auto section_end = section.shdr.sh_addr + section.data.size();

         if (file.externSegm.start_ea < section_end) {
            file.externSegm.start_ea = static_cast<ea_t>(section_end);
         }
      }
   }

   if (importRange.start_ea != 0xFFFFFFFF) {
      file.externSegm.start_ea = (file.externSegm.start_ea + 7) & ~7;
      file.externSegm.end_ea = file.externSegm.start_ea + importRange.size();
      file.importsBaseAddress = importRange.start_ea;
   } else {
      file.externSegm.start_ea = 0;
      file.externSegm.end_ea = 0;
   }
}

static uchar
getSegmentAlign(uint32 addralign)
{
   switch (addralign) {
   case 0:
      return saAbs;
   case 1:
      return saRelByte;
   case 2:
      return saRelWord;
   case 4:
      return saRelDble;
   case 8:
      return saRelQword;
   case 16:
      return saRelPara;
   case 32:
      return saRel32Bytes;
   case 64:
      return saRel64Bytes;
   case 128:
      return saRel128Bytes;
   case 256:
      return saRelPage;
   case 512:
      return saRel512Bytes;
   case 1024:
      return saRel1024Bytes;
   case 2048:
      return saRel2048Bytes;
   case 4096:
      return saRel4K;
   default:
      return saRelDble;
   }
}

static void
addSegments(LoadedFile &file)
{
   const auto &shstrTab = file.sections[file.ehdr.e_shstrndx].data;

   for (auto i = 0u; i < file.sections.size(); ++i) {
      const auto &section = file.sections[i];
      const auto &shdr = section.shdr;
      const char *name = &shstrTab[shdr.sh_name];
      const char *sclass = nullptr;

      if (!(section.shdr.sh_flags & SHF_ALLOC)) {
         continue;
      }

      if (section.shdr.sh_type == SHT_NULL ||
          section.shdr.sh_type == SHT_SYMTAB ||
          section.shdr.sh_type == SHT_STRTAB ||
          section.shdr.sh_type == SHT_RPL_IMPORTS ||
          section.shdr.sh_type == SHT_RPL_EXPORTS) {
         continue;
      }

      segment_t segm;
      segm.align = getSegmentAlign(shdr.sh_addralign);
      segm.comb = scPub;
      segm.perm = SEGPERM_READ;

      if (shdr.sh_flags & SHF_WRITE) {
         segm.perm |= SEGPERM_WRITE;
      }

      if (shdr.sh_flags & SHF_EXECINSTR) {
         segm.perm |= SEGPERM_EXEC;
      }

      segm.bitness = 1;
      segm.flags = 0;
      segm.sel = i;

      if (shdr.sh_type == SHT_NOBITS) {
         sclass = CLASS_BSS;
         segm.type = SEG_BSS;
      } else if (shdr.sh_flags & SHF_EXECINSTR) {
         sclass = CLASS_CODE;
         segm.type = SEG_CODE;
      } else {
         sclass = CLASS_DATA;
         segm.type = SEG_DATA;
      }

      segm.color = DEFCOLOR;

      segm.start_ea = shdr.sh_addr;
      if (section.data.size()) {
         qoff64_t fpos = shdr.sh_offset;
         if (shdr.sh_flags & SHF_RPL_DEFLATED) {
            // We can only use file offset if the section was not compressed.
            fpos = -1;
         }

         segm.end_ea = segm.start_ea + static_cast<ea_t>(section.data.size());
         mem2base(&section.data[0], segm.start_ea, segm.end_ea, fpos);
      } else {
         segm.end_ea = segm.start_ea + shdr.sh_size;
      }

      if (!set_selector(i, 0)) {
         loader_failure("Failed to set selector %u", i);
      }

      if (!add_segm_ex(&segm, name, sclass, 0)) {
         loader_failure("Failed to add segment %u", i);
      }
   }

   if (file.externSegm.start_ea != 0 && file.externSegm.size() != 0) {
      // Add the extern segment
      file.externSegm.align = saRelQword;
      file.externSegm.comb = scPub;
      file.externSegm.perm = SEGPERM_READ | SEGPERM_EXEC;
      file.externSegm.bitness = 1;
      file.externSegm.flags = SFL_LOADER;
      file.externSegm.sel = 255;
      file.externSegm.type = SEG_XTRN;
      file.externSegm.color = DEFCOLOR;

      set_selector(255, 0);
      add_segm_ex(&file.externSegm, ".externs", "XTRN", 0);
   }
}

static bool
getSymbol(LoadedSection &section,
          uint32_t index,
          Elf32_Sym &symbol)
{
   if (section.data.size() < (index + 1) * sizeof(Elf32_Sym)) {
      return false;
   }

   auto symbols = reinterpret_cast<Elf32_Sym *>(&section.data[0]);
   symbol.st_name = swap32(symbols[index].st_name);
   symbol.st_value = swap32(symbols[index].st_value);
   symbol.st_size = swap32(symbols[index].st_size);
   symbol.st_info = symbols[index].st_info;
   symbol.st_other = symbols[index].st_other;
   symbol.st_shndx = swap16(symbols[index].st_shndx);

   return true;
}

static void
loadRelocations(LoadedFile &file)
{
   for (auto i = 0u; i < file.sections.size(); ++i) {
      auto &section = file.sections[i];
      if (section.shdr.sh_type != SHT_RELA) {
         continue;
      }

      auto &symSec = file.sections[section.shdr.sh_link];
      auto &relSec = file.sections[section.shdr.sh_info];

      auto relaNum = section.data.size() / sizeof(Elf32_Rela);
      auto relaArr = reinterpret_cast<Elf32_Rela *>(&section.data[0]);
      for (auto j = 0u; j < relaNum; ++j) {
         auto info = swap32(relaArr[j].r_info);
         auto symIndex = ELF32_R_SYM(info);
         auto relType = ELF32_R_TYPE(info);

         if (relType == R_PPC_NONE) {
            continue;
         }

         Elf32_Sym symbol;
         if (!getSymbol(symSec, symIndex, symbol)) {
            loader_failure(
               "Failed to get symbol %u for relcation %u in section %u",
               symIndex, j, i);
         }

         auto offset = swap32(relaArr[j].r_offset);
         auto addend = static_cast<int32_t>(
            swap32(static_cast<uint32_t>(relaArr[j].r_addend)));
         auto relAddr = symbol.st_value + addend;
         if (symbol.st_value & 0xC0000000) {
            relAddr = (relAddr - file.importsBaseAddress)
                      + file.externSegm.start_ea;
         }

         switch (relType) {
         case R_PPC_ADDR32:
            patch_dword(offset, relAddr);
            break;
         case R_PPC_ADDR16_LO:
            patch_word(offset, relAddr & 0xffff);
            break;
         case R_PPC_ADDR16_HI:
            patch_word(offset, relAddr >> 16);
            break;
         case R_PPC_ADDR16_HA:
            patch_word(offset, (relAddr + 0x8000) >> 16);
            break;
         case R_PPC_REL24:
         {
            auto value = get_original_dword(offset) & ~0x03fffffc;
            value |= ((relAddr - offset) & 0x03fffffc);
            patch_dword(offset, value);
            break;
         }
         case R_PPC_DTPREL32:
            patch_dword(offset, relAddr);
            break;
         case R_PPC_GHS_REL16_HI:
         {
            auto value = (relAddr - offset) >> 16;
            patch_word(offset, value);
            break;
         }
         case R_PPC_GHS_REL16_LO:
         {
            auto value = (relAddr - offset) & 0xffff;
            patch_word(offset, value);
            break;
         }
         default:
            msg("Unsupported relocation type %u", relType);
         }
      }
   }
}

static void
loadSymbols(LoadedFile &file)
{
   for (auto i = 0u; i < file.sections.size(); ++i) {
      auto &section = file.sections[i];
      if (section.shdr.sh_type != SHT_SYMTAB) {
         continue;
      }

      auto symStrTab = &file.sections[section.shdr.sh_link].data[0];
      auto symNum = section.data.size() / sizeof(Elf32_Sym);

      for (auto j = 0u; j < symNum; ++j) {
         Elf32_Sym sym;
         if (!getSymbol(section, j, sym)) {
            continue;
         }

         auto binding = ELF_ST_BIND(sym.st_info);
         auto type = ELF_ST_TYPE(sym.st_info);
         auto &symSec = file.sections[sym.st_shndx];
         auto name = symStrTab + sym.st_name;
         auto addr = sym.st_value;

         if (type == STT_FUNC || type == STT_OBJECT) {
            if (symSec.shdr.sh_type == SHT_RPL_IMPORTS) {
               addr = (addr - file.importsBaseAddress)
                      + file.externSegm.start_ea;
               symSec.importNode.supset(addr, name);
            }
         }

         switch (type) {
         case STT_FILE:
            add_extra_line(addr, true, "File: %s", name);
            break;
         case STT_FUNC:
         {
            force_name(addr, name);
            auto_make_proc(addr);
            break;
         }
         case STT_OBJECT:
            force_name(addr, name);
            create_dword(addr + 0, 4);
            create_dword(addr + 4, 4);
            break;
         }
      }
   }
}

static void
loadImports(LoadedFile &file)
{
   for (auto i = 0u; i < file.sections.size(); ++i) {
      auto &section = file.sections[i];
      if (section.shdr.sh_type == SHT_RPL_IMPORTS) {
         auto name = &section.data[8];

         create_dword(section.shdr.sh_addr + 0, 4);
         create_dword(section.shdr.sh_addr + 4, 4);
         create_strlit(section.shdr.sh_addr + 8, strlen(name) + 1, STRTYPE_C);

         import_module(name, NULL, section.importNode, NULL, "CafeOS");
      }
   }
}

static void
loadExports(LoadedFile &file)
{
   qvector<char> &shStrTab = file.sections[file.ehdr.e_shstrndx].data;

   for (auto i = 0u; i < file.sections.size(); ++i) {
      auto &section = file.sections[i];
      if (section.shdr.sh_type != SHT_RPL_EXPORTS) {
         continue;
      }

      // Name is .fexports for functions and .dexports for data
      auto isFunctionExport = (shStrTab[section.shdr.sh_name + 1] == 'f');
      auto numExports = swap32(*(uint32 *)&section.data[0]);
      for (auto j = 0u; j < numExports; ++j) {
         if (isFunctionExport) {
            auto offset = (j * 8) + 8;
            auto addr = swap32(*(uint32 *)&section.data[offset + 0]);
            auto name_offset = swap32(*(uint32 *)&section.data[offset + 4])
                               & ~EXN_RPL_TLS;

            // Create entry point
            auto_make_proc(addr);
            add_entry(addr, addr, &section.data[name_offset], true);
         }
      }
   }
}

static void
setSdaBase(LoadedFile &file)
{
   uval_t sdaBase = 0xFFFFFFFF;
   uval_t sda2Base = 0xFFFFFFFF;
   qvector<char> &shStrTab = file.sections[file.ehdr.e_shstrndx].data;

   for (auto i = 0u; i < file.sections.size(); ++i) {
      auto &section = file.sections[i];

      if (strcmp(&shStrTab[section.shdr.sh_name], ".sdata") == 0) {
         sdaBase = section.shdr.sh_addr + 0x8000;
      } else if (strcmp(&shStrTab[section.shdr.sh_name], ".sdata2") == 0) {
         sda2Base = section.shdr.sh_addr + 0x8000;
      }
   }

   ph.set_idp_options("PPC_SDA_BASE", IDPOPT_NUM, &sdaBase);
   ph.set_idp_options("PPC_TOC", IDPOPT_NUM, &sda2Base);
}

static void
setProcessorOptions()
{
   set_processor_type("ppc:PAIRED", SETPROC_LOADER);

   // Enable aggressive LIS/ADDI resolution
   int lisoff = 1;
   ph.set_idp_options("PPC_LISOFF", IDPOPT_BIT, &lisoff);
}

static void
setCompilerOptions()
{
   compiler_info_t ci;
   ci.id = COMP_GNU;
   ci.cm = CM_CC_FASTCALL | CM_M_NN | CM_N32_F48;
   ci.size_i = 4;
   ci.size_b = 4;
   ci.size_e = 4;
   ci.defalign = 4;
   ci.size_s = 2;
   ci.size_l = 4;
   ci.size_ll = 8;
   ci.size_ldbl = 8;
   set_compiler(ci, SETCOMP_OVERRIDE, "sysv");
   append_abi_opts("sysv-eabi-hard_float-ldbl_is_dbl");
}

static int idaapi
acceptFile(qstring *fileformatname, /* [out] */
           qstring *processor,      /* [out] */
           linput_t *li,
           const char *filename)
{
   Elf32_Ehdr ehdr;
   qstring errorMsg;
   if (!loadElfHeader(li, ehdr, errorMsg)) {
      return 0;
   }

   *processor = "ppc";
   *fileformatname = "Wii U RPL";
   return ACCEPT_FIRST | 1;
}

static void idaapi
loadFile(linput_t *li,
         ushort neflags,
         const char *fileformatname)
{
   LoadedFile file;
   qstring errorMsg;

   setProcessorOptions();
   setCompilerOptions();

   if (!loadElfHeader(li, file.ehdr, errorMsg)) {
      loader_failure(errorMsg.c_str());
   }

   loadSections(li, file);
   addSegments(file);

   loadSymbols(file);
   loadRelocations(file);

   loadImports(file);
   loadExports(file);

   setSdaBase(file);
}

loader_t ida_module_data LDSC =
{
  IDP_INTERFACE_VERSION,
  0, // flags
  acceptFile,
  loadFile,
  NULL, // save_file
  NULL, // move_segm
  NULL, // process_archive
};
