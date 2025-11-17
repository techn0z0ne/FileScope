/*
 * FileScope: Standalone pixel-view-based file analyser and dissector by techn0z0ne (somedudefrom2021@gmail.com), 2025
 *
 * Based on Bastian Molkenthin aka Sunshine2k project
 * www.sunshine2k.de | www.bastian-molkenthin.de
 *
 * Class to load an 32bit ELF file and get the main file parameters.
 *
 * DOES NOT SUPPORT 64 BIT ELF - due to lack of native 64bit values in Typescript /  Javascript.
 * It still tries to load 64 bit ELF, but this only works if the upper 32bit of all 64bit values ar zero.
*/

var ELFModel;
(function (ELFModel) {
    (function (ELFFileLoadResult) {
        ELFFileLoadResult[ELFFileLoadResult["OK"] = 0] = "OK";
        ELFFileLoadResult[ELFFileLoadResult["INVALID_ELF"] = 1] = "INVALID_ELF";
    })(ELFModel.ELFFileLoadResult || (ELFModel.ELFFileLoadResult = {}));
    var ELFFileLoadResult = ELFModel.ELFFileLoadResult;
    /**
     * Class to access the content of a loaded ELF file.
     */
    var ELFFileAccess = (function () {
        function ELFFileAccess(fileBytes) {
            this.fileContent = fileBytes;
            this.dataViewer = new DataView(fileBytes);
            this.littleEndian = false; /* big-endian by default */
        }
        ELFFileAccess.prototype.setLittleEndian = function (le) {
            this.littleEndian = le;
        };
        ELFFileAccess.prototype.isLittleEndian = function () {
            return this.littleEndian;
        };
        ELFFileAccess.prototype.getDataView = function () {
            return this.dataViewer;
        };
        ELFFileAccess.prototype.getFileContent = function () {
            return this.fileContent;
        };
        ELFFileAccess.prototype.ReadByteString = function (strStartOffset, strMaxLength) {
            /* find actual length of string - null-terminated */
            var length = strMaxLength;
            for (var i = 0; i < strMaxLength; i++) {
                if (strStartOffset + i >= this.dataViewer.byteLength || this.dataViewer.getUint8(strStartOffset + i) == 0) {
                    length = i;
                    break;
                }
            }
            /* read string */
            var str = "";
            for (var i = 0; i < length; i++) {
                str = str + String.fromCharCode(this.dataViewer.getUint8(strStartOffset + i));
            }
            return str;
        };
        return ELFFileAccess;
    })();
    ELFModel.ELFFileAccess = ELFFileAccess;
    /**
     * Represents one element of an ELF file with it's file offset and value.
     */
    var ELFElement = (function () {
        function ELFElement(fa, offset, valueSizeInBytes) {
            if (valueSizeInBytes == 1) {
                this.value = fa.getDataView().getUint8(offset);
            }
            else if (valueSizeInBytes == 2) {
                this.value = fa.getDataView().getUint16(offset, fa.isLittleEndian());
            }
            else if (valueSizeInBytes == 4) {
                this.value = fa.getDataView().getUint32(offset, fa.isLittleEndian());
            }
            else if (valueSizeInBytes == 8) {
                /* no native support for 64 bit values */
                this.value = fa.getDataView().getUint32(offset, fa.isLittleEndian());
                this.value2 = fa.getDataView().getUint32(offset + 4, fa.isLittleEndian());
            }
            else {
                this.value = 0;
            }
            this.offset = offset;
            this.valueSizeInBytes = valueSizeInBytes;
            this.description = function () { return ""; };
            this.FA = fa;
        }
        ELFElement.prototype.GetHexValueStr = function (paddingLength) {
            if (this.valueSizeInBytes <= 4) {
                return "0x" + ("00000000" + this.value.toString(16).toUpperCase()).slice(-paddingLength);
            }
            else {
                /* 64 bit */
                if (this.FA.isLittleEndian()) {
                    return "0x" + ("00000000" + this.value2.toString(16).toUpperCase()).slice(-8) +
                        ("00000000" + this.value.toString(16).toUpperCase()).slice(-8);
                }
                else {
                    return "0x" + ("00000000" + this.value.toString(16).toUpperCase()).slice(-8) +
                        ("00000000" + this.value2.toString(16).toUpperCase()).slice(-8);
                }
            }
        };
        ELFElement.prototype.Get32BitValue = function () {
            if (this.valueSizeInBytes <= 4) {
                return this.value;
            }
            else {
                /* return the least significant 32 bits for 64 bit ELF */
                var retVal = this.FA.isLittleEndian() ? this.value : this.value2;
                return retVal;
            }
        };
        return ELFElement;
    })();
    ELFModel.ELFElement = ELFElement;
    /**
     * ELF file header
     */
    var ELFHeader = (function () {
        function ELFHeader(fileAccess) {
            this.FA = fileAccess;
        }
        ELFHeader.prototype.load = function () {
            var _this = this;
            if (this.FA.getDataView().byteLength < 52)
                return ELFFileLoadResult.INVALID_ELF;
            var curOff = 0;
            this.E_ident_mag = new ELFElement(this.FA, curOff, 4);
            curOff += 4;
            this.E_ident_class = new ELFElement(this.FA, curOff, 1);
            this.E_ident_class.description = function () {
                switch (_this.E_ident_class.value) {
                    case 0:
                        return "NONE";
                        break;
                    case 1:
                        return "32 BIT";
                        break;
                    case 2:
                        return "64 BIT";
                        break;
                    default:
                        return "INVALID";
                        break;
                }
            };
            curOff++;
            this.E_ident_data = new ELFElement(this.FA, curOff, 1);
            this.E_ident_data.description = function () {
                switch (_this.E_ident_data.value) {
                    case 0:
                        return "NONE";
                        break;
                    case 1:
                        return "DATA2LSB (Little-Endian)";
                        break;
                    case 2:
                        return "DATA2MSB (Big-Endian)";
                        break;
                    default:
                        return "INVALID";
                        break;
                }
            };
            this.FA.setLittleEndian(this.E_ident_data.value == 1);
            curOff++;
            this.E_ident_version = new ELFElement(this.FA, curOff, 1);
            this.E_ident_version.description = function () {
                switch (_this.E_ident_version.value) {
                    case 0:
                        return "EV_NONE";
                        break;
                    case 1:
                        return "EV_CURRENT";
                        break;
                    default:
                        return "INVALID";
                        break;
                }
            };
            curOff++;
            this.E_ident_OsAbi = new ELFElement(this.FA, curOff, 1);
            this.E_ident_OsAbi.description = function () {
                switch (_this.E_ident_OsAbi.value) {
                    case 0:
                        return "UNIX System V ABI";
                        break;
                    case 1:
                        return "HP-UX operating system";
                        break;
                    case 255:
                        return "Standalone (embedded) application";
                        break;
                    default:
                        return "Unknown";
                        break;
                }
            };
            curOff++;
            this.E_ident_OsAbiVer = new ELFElement(this.FA, curOff, 1);
            curOff++;
            curOff = 16;
            this.E_type = new ELFElement(this.FA, curOff, 2);
            this.E_type.description = function () { return _this.getDescription_EType(); };
            curOff += 2;
            this.E_machine = new ELFElement(this.FA, curOff, 2);
            this.E_machine.description = function () { return _this.getDescription_EMachine(); };
            curOff += 2;
            this.E_version = new ELFElement(this.FA, curOff, 4);
            this.E_version.description = function () {
                switch (_this.E_version.value) {
                    case 0:
                        return "EV_NONE";
                        break;
                    case 1:
                        return "EV_CURRENT";
                        break;
                    default:
                        return "INVALID";
                        break;
                }
            };
            curOff += 4;
            if (this.isELF64()) {
                this.E_Entry = new ELFElement(this.FA, curOff, 8);
                curOff += 8;
                this.E_PhOff = new ELFElement(this.FA, curOff, 8);
                curOff += 8;
                this.E_ShOff = new ELFElement(this.FA, curOff, 8);
                curOff += 8;
            }
            else {
                this.E_Entry = new ELFElement(this.FA, curOff, 4);
                curOff += 4;
                this.E_PhOff = new ELFElement(this.FA, curOff, 4);
                curOff += 4;
                this.E_ShOff = new ELFElement(this.FA, curOff, 4);
                curOff += 4;
            }
            this.E_Flags = new ELFElement(this.FA, curOff, 4);
            curOff += 4;
            this.E_Ehsize = new ELFElement(this.FA, curOff, 2);
            curOff += 2;
            this.E_Phentsize = new ELFElement(this.FA, curOff, 2);
            curOff += 2;
            this.E_Phnum = new ELFElement(this.FA, curOff, 2);
            curOff += 2;
            this.E_Shentsize = new ELFElement(this.FA, curOff, 2);
            curOff += 2;
            this.E_Shnum = new ELFElement(this.FA, curOff, 2);
            curOff += 2;
            this.E_Shstrndx = new ELFElement(this.FA, curOff, 2);
            curOff += 2;
            return ELFFileLoadResult.OK;
        };
        ELFHeader.prototype.isELF64 = function () {
            return this.E_ident_class.value == 2;
        };
        ELFHeader.prototype.GetSectionNameStringTableIndex = function () {
            return this.E_Shstrndx.value;
        };
        ELFHeader.prototype.getDescription_EType = function () {
            switch (this.E_type.value) {
                case 0:
                    return "ET_NONE (No file type)";
                    break;
                case 1:
                    return "ET_REL (Relocatable file)";
                    break;
                case 2:
                    return "ET_EXEC (Executable file)";
                    break;
                case 3:
                    return "ET_DYN (Shared object file)";
                    break;
                case 4:
                    return "ET_CORE (Core file)";
                    break;
                case 0xFE00:
                    return "ET_LOOS (Processor-specific)";
                    break;
                case 0xFEFF:
                    return "ET_HIOS (Processor-specific)";
                    break;
                case 0xFF00:
                    return "ET_LOPROC (Processor-specific)";
                    break;
                case 0xFFFF:
                    return "ET_HIPROC (Processor-specific)";
                    break;
                default:
                    return "Unknown";
                    break;
            }
        };
        ELFHeader.prototype.getDescription_EMachine = function () {
            switch (this.E_machine.value) {
                case 0:
                    return "EM_NONE (No machine)";
                    break;
                case 1:
                    return "EM_M32 (AT&T WE 32100)";
                    break;
                case 2:
                    return "EM_SPARC (SPARC)";
                    break;
                case 3:
                    return "EM_386 (Intel 80386)";
                    break;
                case 4:
                    return "EM_68K (Motorola 68000)";
                    break;
                case 5:
                    return "EM_88K (Motorola 88000)";
                    break;
                case 6:
                    return "RESERVED (Reserved for future use)";
                    break;
                case 7:
                    return "EM_860 (Intel 80860)";
                    break;
                case 8:
                    return "EM_MIPS (MIPS I Architecture)";
                    break;
                case 9:
                    return "EM_S370 (IBM System/ 370 Processor)";
                    break;
                case 10:
                    return "EM_MIPS_RS3_LE (MIPS RS3000 Little-endian)";
                    break;
                case 11:
                    return "RESERVED (Reserved for future use)";
                    break;
                case 12:
                    return "RESERVED (Reserved for future use)";
                    break;
                case 13:
                    return "RESERVED (Reserved for future use)";
                    break;
                case 14:
                    return "RESERVED (Reserved for future use)";
                    break;
                case 15:
                    return "EM_PARISC (Hewlett- Packard PA- RISC)";
                    break;
                case 16:
                    return "RESERVED (Reserved for future use)";
                    break;
                case 17:
                    return "EM_VPP500 (Fujitsu VPP500)";
                    break;
                case 18:
                    return "EM_SPARC32PS (Enhanced instruction set SPARC)";
                    break;
                case 19:
                    return "EM_960 (Intel 80960)";
                    break;
                case 20:
                    return "EM_PPC (PowerPC)";
                    break;
                case 21:
                    return "EM_PPC64 (64-bit PowerPC)";
                    break;
                case 22:
                    return "EM_S390 (IBM System/390 Processor)";
                    break;
                case 23:
                    return "RESERVED (Reserved for future use)";
                    break;
                case 24:
                    return "RESERVED (Reserved for future use)";
                    break;
                case 25:
                    return "RESERVED (Reserved for future use)";
                    break;
                case 26:
                    return "RESERVED (Reserved for future use)";
                    break;
                case 27:
                    return "RESERVED (Reserved for future use)";
                    break;
                case 28:
                    return "RESERVED (Reserved for future use)";
                    break;
                case 29:
                    return "RESERVED (Reserved for future use)";
                    break;
                case 30:
                    return "RESERVED (Reserved for future use)";
                    break;
                case 31:
                    return "RESERVED (Reserved for future use)";
                    break;
                case 32:
                    return "RESERVED (Reserved for future use)";
                    break;
                case 33:
                    return "RESERVED (Reserved for future use)";
                    break;
                case 34:
                    return "RESERVED (Reserved for future use)";
                    break;
                case 35:
                    return "RESERVED (Reserved for future use)";
                    break;
                case 36:
                    return "EM_V800(NEC V800)";
                    break;
                case 37:
                    return "EM_FR20(Fujitsu FR20)";
                    break;
                case 38:
                    return "EM_RH32(TRW RH- 32)";
                    break;
                case 39:
                    return "EM_RCE (Motorola RCE)";
                    break;
                case 40:
                    return "EM_ARM (Advanced RISC Machines ARM)";
                    break;
                case 41:
                    return "EM_ALPHA (Digital Alpha)";
                    break;
                case 42:
                    return "EM_SH (Hitachi SH)";
                    break;
                case 43:
                    return "EM_SPARCV9 (SPARC Version 9)";
                    break;
                case 44:
                    return "EM_TRICORE (Siemens TriCore embedded processor)";
                    break;
                case 45:
                    return "EM_ARC (Argonaut RISC Core, Argonaut Technologies Inc.)";
                    break;
                case 46:
                    return "EM_H8_300 (Hitachi H8/ 300)";
                    break;
                case 47:
                    return "EM_H8_300H (Hitachi H8/ 300H)";
                    break;
                case 48:
                    return "EM_H8S (Hitachi H8S)";
                    break;
                case 49:
                    return "EM_H8_500 (Hitachi H8/ 500)";
                    break;
                case 50:
                    return "EM_IA_64 (Intel IA- 64 processor architecture)";
                    break;
                case 51:
                    return "EM_MIPS_X (Stanford MIPS- X)";
                    break;
                case 52:
                    return "EM_COLDFIRE (Motorola ColdFire)";
                    break;
                case 53:
                    return "EM_68HC12 (Motorola M68HC12)";
                    break;
                case 54:
                    return "EM_MMA (Fujitsu MMA Multimedia Accelerator)";
                    break;
                case 55:
                    return "EM_PCP (Siemens PCP)";
                    break;
                case 56:
                    return "EM_NCPU (Sony nCPU embedded RISC processor)";
                    break;
                case 57:
                    return "EM_NDR1 (Denso NDR1 microprocessor)";
                    break;
                case 58:
                    return "EM_STARCORE (Motorola Star* Core processor)";
                    break;
                case 59:
                    return "EM_ME16 (Toyota ME16 processor)";
                    break;
                case 60:
                    return "EM_ST100 (STMicroelectronics ST100 processor)";
                    break;
                case 61:
                    return "EM_TINYJ (Advanced Logic Corp.TinyJ embedded processor family)";
                    break;
                case 62:
                    return "EM_X86_64 (AMD x86- 64 architecture)";
                    break;
                case 63:
                    return "EM_PDSP (Sony DSP Processor)";
                    break;
                case 64:
                    return "EM_PDP10 (Digital Equipment Corp.PDP - 10)";
                    break;
                case 65:
                    return "EM_PDP11 (Digital Equipment Corp.PDP - 11)";
                    break;
                case 66:
                    return "EM_FX66 (Siemens FX66 microcontroller)";
                    break;
                case 67:
                    return "EM_ST9PLUS (STMicroelectronics ST9+ 8 / 16 bit microcontroller)";
                    break;
                case 68:
                    return "EM_ST7 (STMicroelectronics ST7 8- bit microcontroller)";
                    break;
                case 69:
                    return "EM_68HC16 (Motorola MC68HC16 Microcontroller)";
                    break;
                case 70:
                    return "EM_68HC11 (Motorola MC68HC11 Microcontroller)";
                    break;
                case 71:
                    return "EM_68HC08 (Motorola MC68HC08 Microcontroller)";
                    break;
                case 72:
                    return "EM_68HC05 (Motorola MC68HC05 Microcontroller)";
                    break;
                case 73:
                    return "EM_SVX (Silicon Graphics SVx)";
                    break;
                case 74:
                    return "EM_ST19 (STMicroelectronics ST19 8- bit microcontroller)";
                    break;
                case 75:
                    return "EM_VAX (Digital VAX)";
                    break;
                case 76:
                    return "EM_CRIS (Axis Communications 32- bit embedded processor)";
                    break;
                case 77:
                    return "EM_JAVELIN (Infineon Technologies 32- bit embedded processor)";
                    break;
                case 78:
                    return "EM_FIREPATH (Element 14 64- bit DSP Processor)";
                    break;
                case 79:
                    return "EM_ZSP (LSI Logic 16- bit DSP Processor)";
                    break;
                case 80:
                    return "EM_MMIX (Donald Knuth's educational 64-bit processor)";
                    break;
                case 81:
                    return "EM_HUANY (Harvard University machine- independent object files)";
                    break;
                case 82:
                    return "EM_PRISM (SiTera Prism)";
                    break;
                case 83:
                    return "EM_AVR (Atmel AVR 8- bit microcontroller)";
                    break;
                case 84:
                    return "EM_FR30 (Fujitsu FR30)";
                    break;
                case 85:
                    return "EM_D10V (Mitsubishi D10V)";
                    break;
                case 86:
                    return "EM_D30V (Mitsubishi D30V)";
                    break;
                case 87:
                    return "EM_V850 (NEC v850)";
                    break;
                case 88:
                    return "EM_M32R (Mitsubishi M32R)";
                    break;
                case 89:
                    return "EM_MN10300(Matsushita MN10300)";
                    break;
                case 90:
                    return "EM_MN10200(Matsushita MN10200)";
                    break;
                case 91:
                    return "EM_PJ (picoJava)";
                    break;
                case 92:
                    return "EM_OPENRISC (OpenRISC 32- bit embedded processor)";
                    break;
                case 93:
                    return "EM_ARC_A5 (ARC Cores Tangent- A5)";
                    break;
                case 94:
                    return "EM_XTENSA (Tensilica Xtensa Architecture)";
                    break;
                case 95:
                    return "EM_VIDEOCORE (Alphamosaic VideoCore processor)";
                    break;
                case 96:
                    return "EM_TMM_GPP (Thompson Multimedia General Purpose Processor)";
                    break;
                case 97:
                    return "EM_NS32K (National Semiconductor 32000 series)";
                    break;
                case 98:
                    return "EM_TPC (Tenor Network TPC processor)";
                    break;
                case 99:
                    return "EM_SNP1K (Trebia SNP 1000 processor)";
                    break;
                case 100:
                    return "EM_ST200 (STMicroelectronic)";
                    break;
                default:
                    return "Unknown";
                    break;
            }
        };
        return ELFHeader;
    })();
    ELFModel.ELFHeader = ELFHeader;
    /**
     * ELF section table
     */
    var ELFSectionHeaderTable = (function () {
        function ELFSectionHeaderTable(headerIndex, fileAccess, elfFile) {
            this.FA = fileAccess;
            this.headerIndex = headerIndex;
            this.elfFile = elfFile;
        }
        ELFSectionHeaderTable.prototype.load = function (startAddress) {
            var _this = this;
            var curOff = startAddress;
            var elemSize = this.elfFile.elfHeader.isELF64() ? 8 : 4;
            this.Sh_Name = new ELFElement(this.FA, curOff, 4);
            this.Sh_Name.description = function () { return _this.getDescription_Name(); };
            curOff += 4;
            this.Sh_Type = new ELFElement(this.FA, curOff, 4);
            this.Sh_Type.description = function () { return _this.getDescription_Type(); };
            curOff += 4;
            this.Sh_Flags = new ELFElement(this.FA, curOff, elemSize);
            this.Sh_Flags.description = function () { return _this.getDescription_Flags(); };
            curOff += elemSize;
            this.Sh_Addr = new ELFElement(this.FA, curOff, elemSize);
            curOff += elemSize;
            this.Sh_Offset = new ELFElement(this.FA, curOff, elemSize);
            curOff += elemSize;
            this.Sh_Size = new ELFElement(this.FA, curOff, elemSize);
            curOff += elemSize;
            this.Sh_Link = new ELFElement(this.FA, curOff, 4);
            curOff += 4;
            this.Sh_Info = new ELFElement(this.FA, curOff, 4);
            curOff += 4;
            this.Sh_Addralign = new ELFElement(this.FA, curOff, elemSize);
            curOff += elemSize;
            this.Sh_Entsize = new ELFElement(this.FA, curOff, elemSize);
            curOff += elemSize;
        };
        ELFSectionHeaderTable.prototype.getName = function () {
            return this.Sh_Name.description();
        };
        ELFSectionHeaderTable.prototype.getDescription_Type = function () {
            if (this.elfFile.elfCompactMode) {
                switch (this.Sh_Type.value) {
                    case ELFSectionHeaderTable.SHT_NULL:
                        return "SHT_NULL";
                        break;
                    case ELFSectionHeaderTable.SHT_PROGBITS:
                        return "SHT_PROGBITS";
                        break;
                    case ELFSectionHeaderTable.SHT_SYMTAB:
                        return "SHT_SYMTAB";
                        break;
                    case ELFSectionHeaderTable.SHT_STRTAB:
                        return "SHT_STRTAB";
                        break;
                    case ELFSectionHeaderTable.SHT_RELA:
                        return "SHT_RELA";
                        break;
                    case ELFSectionHeaderTable.SHT_HASH:
                        return "SHT_HASH";
                        break;
                    case ELFSectionHeaderTable.SHT_DYNAMIC:
                        return "SHT_DYNAMIC";
                        break;
                    case ELFSectionHeaderTable.SHT_NOTE:
                        return "SHT_NOTE";
                        break;
                    case ELFSectionHeaderTable.SHT_NOBITS:
                        return "SHT_NOBITS";
                        break;
                    case ELFSectionHeaderTable.SHT_REL:
                        return "SHT_REL";
                        break;
                    case ELFSectionHeaderTable.SHT_SHLIB:
                        return "SHT_SHLIB";
                        break;
                    case ELFSectionHeaderTable.SHT_DYNSYM:
                        return "SHT_DYNSYM";
                        break;
                    case ELFSectionHeaderTable.SHT_INIT_ARRAY:
                        return "SHT_INIT_ARRAY";
                        break;
                    case ELFSectionHeaderTable.SHT_FINI_ARRAY:
                        return "SHT_FINI_ARRAY";
                        break;
                    case ELFSectionHeaderTable.SHT_PREINIT_ARRAY:
                        return "SHT_PREINIT_ARRAY";
                        break;
                    case ELFSectionHeaderTable.SHT_GROUP:
                        return "SHT_GROUP";
                        break;
                    case ELFSectionHeaderTable.SHT_SYMTAB_SHNDX:
                        return "SHT_SYMTAB_SHNDX";
                        break;
                    default:
                        return "Unknown";
                        break;
                }
            }
            else {
                switch (this.Sh_Type.value) {
                    case ELFSectionHeaderTable.SHT_NULL:
                        return "SHT_NULL (Unused section header)";
                        break;
                    case ELFSectionHeaderTable.SHT_PROGBITS:
                        return "SHT_PROGBITS (Defined by program)";
                        break;
                    case ELFSectionHeaderTable.SHT_SYMTAB:
                        return "SHT_SYMTAB (Linker symbol table)";
                        break;
                    case ELFSectionHeaderTable.SHT_STRTAB:
                        return "SHT_STRTAB (String table)";
                        break;
                    case ELFSectionHeaderTable.SHT_RELA:
                        return "SHT_RELA (Relocation table)";
                        break;
                    case ELFSectionHeaderTable.SHT_HASH:
                        return "SHT_HASH (Symbol hash table)";
                        break;
                    case ELFSectionHeaderTable.SHT_DYNAMIC:
                        return "SHT_DYNAMIC (Dynamic linking table)";
                        break;
                    case ELFSectionHeaderTable.SHT_NOTE:
                        return "SHT_NOTE (Note information)";
                        break;
                    case ELFSectionHeaderTable.SHT_NOBITS:
                        return "SHT_NOBITS (Uninitialized space)";
                        break;
                    case ELFSectionHeaderTable.SHT_REL:
                        return "SHT_REL (Relocation table)";
                        break;
                    case ELFSectionHeaderTable.SHT_SHLIB:
                        return "SHT_SHLIB (Reserved table)";
                        break;
                    case ELFSectionHeaderTable.SHT_DYNSYM:
                        return "SHT_DYNSYM (Dynamic loader symbol table)";
                        break;
                    case ELFSectionHeaderTable.SHT_INIT_ARRAY:
                        return "SHT_INIT_ARRAY (Array of pointers to initialization functions table)";
                        break;
                    case ELFSectionHeaderTable.SHT_FINI_ARRAY:
                        return "SHT_FINI_ARRAY (Array of pointers to termination functions table)";
                        break;
                    case ELFSectionHeaderTable.SHT_PREINIT_ARRAY:
                        return "SHT_PREINIT_ARRAY (Array of pointers to pre-initialization functions table)";
                        break;
                    case ELFSectionHeaderTable.SHT_GROUP:
                        return "SHT_GROUP (Section Group)";
                        break;
                    case ELFSectionHeaderTable.SHT_SYMTAB_SHNDX:
                        return "SHT_SYMTAB_SHNDX (Extended section indices)";
                        break;
                    default:
                        return "Unknown";
                        break;
                }
            }
        };
        ELFSectionHeaderTable.prototype.getDescription_Flags = function () {
            var s = "";
            if ((this.Sh_Flags.value & ELFSectionHeaderTable.SHF_W) != 0) {
                s += "Write";
            }
            if ((this.Sh_Flags.value & ELFSectionHeaderTable.SHF_ALLOC) != 0) {
                if (s.length > 0)
                    s += "|";
                s += "Alloc";
            }
            if ((this.Sh_Flags.value & ELFSectionHeaderTable.SHF_EXECINSTR) != 0) {
                if (s.length > 0)
                    s += "|";
                s += "Exec";
            }
            if ((this.Sh_Flags.value & ELFSectionHeaderTable.SHF_MERGE) != 0) {
                if (s.length > 0)
                    s += "|";
                s += "Merge";
            }
            if ((this.Sh_Flags.value & ELFSectionHeaderTable.SHF_STRINGS) != 0) {
                if (s.length > 0)
                    s += "|";
                s += "Strings";
            }
            if ((this.Sh_Flags.value & ELFSectionHeaderTable.SHF_INFO_LINK) != 0) {
                if (s.length > 0)
                    s += "|";
                s += "InfoLink";
            }
            if ((this.Sh_Flags.value & ELFSectionHeaderTable.SHF_LINK_ORDER) != 0) {
                if (s.length > 0)
                    s += "|";
                s += "LinkOrder";
            }
            if ((this.Sh_Flags.value & ELFSectionHeaderTable.SHF_OS_NONCONFORMING) != 0) {
                if (s.length > 0)
                    s += "|";
                s += "OS";
            }
            if ((this.Sh_Flags.value & ELFSectionHeaderTable.SHF_GROUP) != 0) {
                if (s.length > 0)
                    s += "|";
                s += "GROUP";
            }
            if ((this.Sh_Flags.value & ELFSectionHeaderTable.SHF_TLS) != 0) {
                if (s.length > 0)
                    s += "|";
                s += "TLS";
            }
            if ((this.Sh_Flags.value & ELFSectionHeaderTable.SHF_AMD64_LARGE) != 0) {
                if (s.length > 0)
                    s += "|";
                s += "Large";
            }
            if ((this.Sh_Flags.value & ELFSectionHeaderTable.SHF_ORDERED) != 0) {
                if (s.length > 0)
                    s += "|";
                s += "Ordered";
            }
            if ((this.Sh_Flags.value & ELFSectionHeaderTable.SHF_EXCLUDE) != 0) {
                if (s.length > 0)
                    s += "|";
                s += "Excluded";
            }
            if ((this.Sh_Flags.value & ELFSectionHeaderTable.SHF_MASKPROC) != 0) {
                if (s.length > 0)
                    s += "|";
                s += "Processor-specific";
            }
            return s;
        };
        ELFSectionHeaderTable.prototype.getDescription_Name = function () {
            var secNameSectionIdx;
            secNameSectionIdx = this.elfFile.elfHeader.E_Shstrndx.value;
            if (secNameSectionIdx != 0) {
                /* get section containing section names */
                var strSec = this.elfFile.elfSectionHeaderTables[secNameSectionIdx];
                /* get file offset where section name starts */
                var strStartOffset = strSec.Sh_Offset.Get32BitValue() + this.Sh_Name.Get32BitValue();
                /* specify theoretical upper bound for length in case of errors */
                var strMaxLength = strSec.Sh_Offset.Get32BitValue() + strSec.Sh_Size.Get32BitValue() - strStartOffset;
                /* read actual string */
                var str = "";
                str = this.FA.ReadByteString(strStartOffset, strMaxLength);
                return str;
            }
            else {
                return "";
            }
        };
        ELFSectionHeaderTable.SHT_NULL = 0;
        ELFSectionHeaderTable.SHT_PROGBITS = 1;
        ELFSectionHeaderTable.SHT_SYMTAB = 2;
        ELFSectionHeaderTable.SHT_STRTAB = 3;
        ELFSectionHeaderTable.SHT_RELA = 4;
        ELFSectionHeaderTable.SHT_HASH = 5;
        ELFSectionHeaderTable.SHT_DYNAMIC = 6;
        ELFSectionHeaderTable.SHT_NOTE = 7;
        ELFSectionHeaderTable.SHT_NOBITS = 8;
        ELFSectionHeaderTable.SHT_REL = 9;
        ELFSectionHeaderTable.SHT_SHLIB = 10;
        ELFSectionHeaderTable.SHT_DYNSYM = 11;
        ELFSectionHeaderTable.SHT_INIT_ARRAY = 14;
        ELFSectionHeaderTable.SHT_FINI_ARRAY = 15;
        ELFSectionHeaderTable.SHT_PREINIT_ARRAY = 16;
        ELFSectionHeaderTable.SHT_GROUP = 17;
        ELFSectionHeaderTable.SHT_SYMTAB_SHNDX = 18;
        ELFSectionHeaderTable.SHF_W = 0x01; /* Contains writable data */
        ELFSectionHeaderTable.SHF_ALLOC = 0x02; /* Write permission */
        ELFSectionHeaderTable.SHF_EXECINSTR = 0x04; /* Contains executable instructions */
        ELFSectionHeaderTable.SHF_MERGE = 0x10; /* Can be merge to eliminate duplicate */
        ELFSectionHeaderTable.SHF_STRINGS = 0x20; /* Contains null-terminated character strings */
        ELFSectionHeaderTable.SHF_INFO_LINK = 0x40; /* Sh_info field has section header table index */
        ELFSectionHeaderTable.SHF_LINK_ORDER = 0x80; /* Contains special ordering requirements */
        ELFSectionHeaderTable.SHF_OS_NONCONFORMING = 0x100; /* Requires requires special OS-specific processing */
        ELFSectionHeaderTable.SHF_GROUP = 0x200; /* Member of section group */
        ELFSectionHeaderTable.SHF_TLS = 0x400; /* Contains thread-local storage */
        ELFSectionHeaderTable.SHF_AMD64_LARGE = 0x10000000; /* Has more than 2 Gbyte */
        ELFSectionHeaderTable.SHF_ORDERED = 0x40000000; /* Ordered */
        ELFSectionHeaderTable.SHF_EXCLUDE = 0x80000000; /* Excluded */
        ELFSectionHeaderTable.SHF_MASKPROC = 0xF0000000; /* Reserved processor-specific bit mask */
        return ELFSectionHeaderTable;
    })();
    ELFModel.ELFSectionHeaderTable = ELFSectionHeaderTable;
    /**
     * ELF program header table
     */
    var ELFProgramHeaderTable = (function () {
        function ELFProgramHeaderTable(elfFile, headerIndex, fileAccess) {
            this.FA = fileAccess;
            this.headerIndex = headerIndex;
            this.elfFile = elfFile;
        }
        ELFProgramHeaderTable.prototype.load = function (startAddress, elfHeader) {
            var _this = this;
            var curOff = startAddress;
            var elemSize = elfHeader.isELF64() ? 8 : 4;
            if (elfHeader.isELF64()) {
                this.P_Type = new ELFElement(this.FA, curOff, 4);
                this.P_Type.description = function () { return _this.getDescription_PType(); };
                curOff += 4;
                this.P_Flags = new ELFElement(this.FA, curOff, 4);
                curOff += 4;
                this.P_Flags.description = function () { return _this.getDescription_PFlags(); };
                this.P_Offset = new ELFElement(this.FA, curOff, elemSize);
                curOff += elemSize;
                this.P_VAddr = new ELFElement(this.FA, curOff, elemSize);
                curOff += elemSize;
                this.P_PAddr = new ELFElement(this.FA, curOff, elemSize);
                curOff += elemSize;
                this.P_FileSz = new ELFElement(this.FA, curOff, elemSize);
                curOff += elemSize;
                this.P_MemSz = new ELFElement(this.FA, curOff, elemSize);
                curOff += elemSize;
                this.P_Align = new ELFElement(this.FA, curOff, elemSize);
                curOff += elemSize;
            }
            else {
                this.P_Type = new ELFElement(this.FA, curOff, 4);
                this.P_Type.description = function () { return _this.getDescription_PType(); };
                curOff += 4;
                this.P_Offset = new ELFElement(this.FA, curOff, elemSize);
                curOff += elemSize;
                this.P_VAddr = new ELFElement(this.FA, curOff, elemSize);
                curOff += elemSize;
                this.P_PAddr = new ELFElement(this.FA, curOff, elemSize);
                curOff += elemSize;
                this.P_FileSz = new ELFElement(this.FA, curOff, elemSize);
                curOff += elemSize;
                this.P_MemSz = new ELFElement(this.FA, curOff, elemSize);
                curOff += elemSize;
                this.P_Flags = new ELFElement(this.FA, curOff, 4);
                curOff += 4;
                this.P_Flags.description = function () { return _this.getDescription_PFlags(); };
                this.P_Align = new ELFElement(this.FA, curOff, elemSize);
                curOff += elemSize;
            }
        };
        ELFProgramHeaderTable.prototype.getDescription_PType = function () {
            if (this.elfFile.elfCompactMode) {
                switch (this.P_Type.value) {
                    case 0:
                        return "PT_NULL";
                        break;
                    case 1:
                        return "PT_LOAD";
                        break;
                    case 2:
                        return "PT_DYNAMIC";
                        break;
                    case 3:
                        return "PT_INTERP";
                        break;
                    case 4:
                        return "PT_NOTE";
                        break;
                    case 5:
                        return "PT_SHLIB";
                        break;
                    case 6:
                        return "PT_PHDR";
                        break;
                    case 7:
                        return "PT_TLS";
                        break;
                    case 0x60000000:
                        return "PT_LOOS";
                        break;
                    case 0x6FFFFFFF:
                        return "PT_HIOS";
                        break;
                    case 0x70000000:
                        return "PT_LOPROC";
                        break;
                    case 0x7FFFFFFF:
                        return "PT_HIPROC";
                        break;
                    default:
                        return "Unknown";
                        break;
                }
            }
            else {
                switch (this.P_Type.value) {
                    case 0:
                        return "PT_NULL (Unused entry)";
                        break;
                    case 1:
                        return "PT_LOAD (Loadable segment)";
                        break;
                    case 2:
                        return "PT_DYNAMIC (Dynamic linking tables)";
                        break;
                    case 3:
                        return "PT_INTERP (Program interpreter path name)";
                        break;
                    case 4:
                        return "PT_NOTE (Note sections)";
                        break;
                    case 5:
                        return "PT_SHLIB (Reserved)";
                        break;
                    case 6:
                        return "PT_PHDR (Program header table)";
                        break;
                    case 7:
                        return "PT_TLS (Thread-local storage)";
                        break;
                    case 0x60000000:
                        return "PT_LOOS (Environment-speciﬁc use)";
                        break;
                    case 0x6FFFFFFF:
                        return "PT_HIOS";
                        break;
                    case 0x70000000:
                        return "PT_LOPROC (Processor-speciﬁc use)";
                        break;
                    case 0x7FFFFFFF:
                        return "PT_HIPROC";
                        break;
                    default:
                        return "Unknown";
                        break;
                }
            }
        };
        ELFProgramHeaderTable.prototype.getDescription_PFlags = function () {
            var PF_X = 0x01; /* Execute permission */
            var PF_W = 0x02; /* Write permission */
            var PF_R = 0x04; /* Read permission */
            var PF_MASKOS = 0x00FF0000; /* Environment-speciﬁc use */
            var PF_MASKPROC = 0xFF000000; /* Environment-speciﬁc use */
            var s = "";
            if ((this.P_Flags.value == PF_MASKOS) || (this.P_Flags.value == PF_MASKPROC)) {
                s = "Environment-speciﬁc use";
            }
            else {
                if ((this.P_Flags.value & PF_X) != 0) {
                    s += "Execute";
                }
                if ((this.P_Flags.value & PF_W) != 0) {
                    if (s.length > 0)
                        s += "|";
                    s += "Write";
                }
                if ((this.P_Flags.value & PF_R) != 0) {
                    if (s.length > 0)
                        s += "|";
                    s += "Read";
                }
            }
            return s;
        };
        return ELFProgramHeaderTable;
    })();
    ELFModel.ELFProgramHeaderTable = ELFProgramHeaderTable;
    /**
     * One entry of ELF symbol table.
     */
    var ELFSymbolTableEntry = (function () {
        function ELFSymbolTableEntry(index, symTable, elfFile) {
            this.index = index;
            this.symTable = symTable;
            this.elfFile = elfFile;
            this.FA = elfFile.elfFileAccess;
        }
        ELFSymbolTableEntry.prototype.load = function (startAddress) {
            var _this = this;
            var curOff = startAddress;
            if (this.elfFile.elfHeader.isELF64()) {
                this.St_name = new ELFElement(this.FA, curOff, 4);
                curOff += 4;
                this.St_info = new ELFElement(this.FA, curOff, 1);
                curOff += 1;
                this.St_other = new ELFElement(this.FA, curOff, 1);
                curOff += 1;
                this.St_shndx = new ELFElement(this.FA, curOff, 2);
                curOff += 2;
                this.St_value = new ELFElement(this.FA, curOff, 8);
                curOff += 8;
                this.St_size = new ELFElement(this.FA, curOff, 8);
                curOff += 8;
            }
            else {
                this.St_name = new ELFElement(this.FA, curOff, 4);
                curOff += 4;
                this.St_value = new ELFElement(this.FA, curOff, 4);
                curOff += 4;
                this.St_size = new ELFElement(this.FA, curOff, 4);
                curOff += 4;
                this.St_info = new ELFElement(this.FA, curOff, 1);
                curOff += 1;
                this.St_other = new ELFElement(this.FA, curOff, 1);
                curOff += 1;
                this.St_shndx = new ELFElement(this.FA, curOff, 2);
                curOff += 2;
            }
            this.St_other.description = function () { return _this.getDescription_StOther(); };
            this.St_info.description = function () { return _this.getDescription_StInfo(); };
            this.St_name.description = function () { return _this.getDescription_StName(); };
        };
        ELFSymbolTableEntry.prototype.getDescription_StOther = function () {
            if (this.elfFile.elfCompactMode) {
                switch (this.St_other.Get32BitValue() & 0x03) {
                    case ELFSymbolTableEntry.STV_DEFAULT:
                        return "DEFAULT";
                        break;
                    case ELFSymbolTableEntry.STV_INTERNAL:
                        return "INTERNAL:";
                        break;
                    case ELFSymbolTableEntry.STV_HIDDEN:
                        return "HIDDEN";
                        break;
                    case ELFSymbolTableEntry.STV_PROTECTED:
                        return "PROTECTED";
                        break;
                    case ELFSymbolTableEntry.STV_EXPORTED:
                        return "EXPORTED";
                        break;
                    case ELFSymbolTableEntry.STV_SINGLETON:
                        return "SINGLETON";
                        break;
                    case ELFSymbolTableEntry.STV_ELIMINATE:
                        return "ELIMINATE:";
                        break;
                    default:
                        return "unknown";
                        break;
                }
            }
            else {
                switch (this.St_other.Get32BitValue() & 0x03) {
                    case ELFSymbolTableEntry.STV_DEFAULT:
                        return "Visibiility: DEFAULT";
                        break;
                    case ELFSymbolTableEntry.STV_INTERNAL:
                        return "Visibiility: INTERNAL:";
                        break;
                    case ELFSymbolTableEntry.STV_HIDDEN:
                        return "Visibiility: HIDDEN";
                        break;
                    case ELFSymbolTableEntry.STV_PROTECTED:
                        return "Visibiility: PROTECTED";
                        break;
                    case ELFSymbolTableEntry.STV_EXPORTED:
                        return "Visibiility: EXPORTED";
                        break;
                    case ELFSymbolTableEntry.STV_SINGLETON:
                        return "Visibiility: SINGLETON";
                        break;
                    case ELFSymbolTableEntry.STV_ELIMINATE:
                        return "Visibiility: ELIMINATE:";
                        break;
                    default:
                        return "Visibiility: unknown";
                        break;
                }
            }
        };
        ELFSymbolTableEntry.prototype.getDescription_StInfo = function () {
            var s = "";
            if (this.elfFile.elfCompactMode) {
                switch (this.St_info.Get32BitValue() >> 4) {
                    case ELFSymbolTableEntry.STB_LOCAL:
                        s += "LOCAL ";
                        break;
                    case ELFSymbolTableEntry.STB_GLOBAL:
                        s += "GLOBAL ";
                        break;
                    case ELFSymbolTableEntry.STB_WEAK:
                        s += "WEAK ";
                        break;
                    case ELFSymbolTableEntry.STB_LOOS:
                        s += "LOOS ";
                        break;
                    case ELFSymbolTableEntry.STB_HIOS:
                        s += "HIOS ";
                        break;
                    case ELFSymbolTableEntry.STB_LOPROC:
                        s += "LOPROC ";
                        break;
                    case ELFSymbolTableEntry.STB_HIPROC:
                        s += "HIPROC ";
                        break;
                    default:
                        s += "Unknown ";
                        break;
                }
                switch (this.St_info.Get32BitValue() & 0x0F) {
                    case ELFSymbolTableEntry.STT_NOTYPE:
                        s += "| NOTYPE";
                        break;
                    case ELFSymbolTableEntry.STT_OBJECT:
                        s += "| OBJECT";
                        break;
                    case ELFSymbolTableEntry.STT_FUNC:
                        s += "| FUNC";
                        break;
                    case ELFSymbolTableEntry.STT_SECTION:
                        s += "| SECTION";
                        break;
                    case ELFSymbolTableEntry.STT_FILE:
                        s += "| FILE";
                        break;
                    case ELFSymbolTableEntry.STT_COMMON:
                        s += "| COMMON";
                        break;
                    case ELFSymbolTableEntry.STT_TLS:
                        s += "| TLS";
                        break;
                    case ELFSymbolTableEntry.STT_LOOS:
                        s += "| LOOS";
                        break;
                    case ELFSymbolTableEntry.STT_HIOS:
                        s += "| HIOS";
                        break;
                    case ELFSymbolTableEntry.STT_LOPROC:
                        s += "| LOPROC";
                        break;
                    case ELFSymbolTableEntry.STT_HIPROC:
                        s += "| HIPROC";
                        break;
                    default:
                        s += "| Unknown ";
                        break;
                }
            }
            else {
                switch (this.St_info.Get32BitValue() >> 4) {
                    case ELFSymbolTableEntry.STB_LOCAL:
                        s += "Binding: LOCAL ";
                        break;
                    case ELFSymbolTableEntry.STB_GLOBAL:
                        s += "Binding: GLOBAL ";
                        break;
                    case ELFSymbolTableEntry.STB_WEAK:
                        s += "Binding: WEAK ";
                        break;
                    case ELFSymbolTableEntry.STB_LOOS:
                        s += "Binding: LOOS ";
                        break;
                    case ELFSymbolTableEntry.STB_HIOS:
                        s += "Binding: HIOS ";
                        break;
                    case ELFSymbolTableEntry.STB_LOPROC:
                        s += "Binding: LOPROC ";
                        break;
                    case ELFSymbolTableEntry.STB_HIPROC:
                        s += "Binding: HIPROC ";
                        break;
                    default:
                        s += "Binding: Unknown ";
                        break;
                }
                switch (this.St_info.Get32BitValue() & 0x0F) {
                    case ELFSymbolTableEntry.STT_NOTYPE:
                        s += "| Type: NOTYPE";
                        break;
                    case ELFSymbolTableEntry.STT_OBJECT:
                        s += "| Type: OBJECT";
                        break;
                    case ELFSymbolTableEntry.STT_FUNC:
                        s += "| Type: FUNC";
                        break;
                    case ELFSymbolTableEntry.STT_SECTION:
                        s += "| Type: SECTION";
                        break;
                    case ELFSymbolTableEntry.STT_FILE:
                        s += "| Type: FILE";
                        break;
                    case ELFSymbolTableEntry.STT_COMMON:
                        s += "| Type: COMMON";
                        break;
                    case ELFSymbolTableEntry.STT_TLS:
                        s += "| Type: TLS";
                        break;
                    case ELFSymbolTableEntry.STT_LOOS:
                        s += "| Type: LOOS";
                        break;
                    case ELFSymbolTableEntry.STT_HIOS:
                        s += "| Type: HIOS";
                        break;
                    case ELFSymbolTableEntry.STT_LOPROC:
                        s += "| Type: LOPROC";
                        break;
                    case ELFSymbolTableEntry.STT_HIPROC:
                        s += "| Type: HIPROC";
                        break;
                    default:
                        s += "Type: Unknown ";
                        break;
                }
            }
            return s;
        };
        ELFSymbolTableEntry.prototype.getDescription_StName = function () {
            var str = "";
            if (this.St_name.Get32BitValue() != 0) {
                var symStrTableIdx = this.symTable.getRefSectionTable().Sh_Link.Get32BitValue();
                if (symStrTableIdx < this.elfFile.getNumOfSectionHeaderTables()) {
                    /* file offset of beginning of section of symbol names */
                    var symStringTableFileOffset = this.elfFile.elfSectionHeaderTables[symStrTableIdx].Sh_Offset.Get32BitValue();
                    /* file offset to beginning of symbol name string */
                    var secNameStringFileOffset = symStringTableFileOffset + this.St_name.Get32BitValue();
                    /* specify theoretical upper bound for length in case of errors */
                    var strMaxLength = symStringTableFileOffset + this.elfFile.elfSectionHeaderTables[symStrTableIdx].Sh_Size.Get32BitValue() - secNameStringFileOffset;
                    /* read actual string */
                    str = this.FA.ReadByteString(secNameStringFileOffset, strMaxLength);
                    return str;
                }
            }
            return str;
        };
        ELFSymbolTableEntry.STV_DEFAULT = 0;
        ELFSymbolTableEntry.STV_INTERNAL = 1;
        ELFSymbolTableEntry.STV_HIDDEN = 2;
        ELFSymbolTableEntry.STV_PROTECTED = 3;
        ELFSymbolTableEntry.STV_EXPORTED = 4;
        ELFSymbolTableEntry.STV_SINGLETON = 5;
        ELFSymbolTableEntry.STV_ELIMINATE = 6;
        ELFSymbolTableEntry.STB_LOCAL = 0;
        ELFSymbolTableEntry.STB_GLOBAL = 1;
        ELFSymbolTableEntry.STB_WEAK = 2;
        ELFSymbolTableEntry.STB_LOOS = 10;
        ELFSymbolTableEntry.STB_HIOS = 12;
        ELFSymbolTableEntry.STB_LOPROC = 13;
        ELFSymbolTableEntry.STB_HIPROC = 15;
        ELFSymbolTableEntry.STT_NOTYPE = 0;
        ELFSymbolTableEntry.STT_OBJECT = 1;
        ELFSymbolTableEntry.STT_FUNC = 2;
        ELFSymbolTableEntry.STT_SECTION = 3;
        ELFSymbolTableEntry.STT_FILE = 4;
        ELFSymbolTableEntry.STT_COMMON = 5;
        ELFSymbolTableEntry.STT_TLS = 6;
        ELFSymbolTableEntry.STT_LOOS = 10;
        ELFSymbolTableEntry.STT_HIOS = 12;
        ELFSymbolTableEntry.STT_LOPROC = 13;
        ELFSymbolTableEntry.STT_HIPROC = 15;
        return ELFSymbolTableEntry;
    })();
    ELFModel.ELFSymbolTableEntry = ELFSymbolTableEntry;
    /**
     * ELF symbol table
     */
    var ELFSymbolTable = (function () {
        function ELFSymbolTable(sectionTable, fileAccess, elffile) {
            this.symTabEntries = [];
            this.FA = fileAccess;
            this.sectionTable = sectionTable;
            this.elffile = elffile;
        }
        ELFSymbolTable.prototype.load = function () {
            var numOfEntrys = (this.sectionTable.Sh_Size.Get32BitValue() / this.sectionTable.Sh_Entsize.Get32BitValue());
            for (var i = 0; i < numOfEntrys; i++) {
                var symEntry = new ELFSymbolTableEntry(i, this, this.elffile);
                symEntry.load(this.sectionTable.Sh_Offset.Get32BitValue() + (i * this.sectionTable.Sh_Entsize.Get32BitValue()));
                this.symTabEntries.push(symEntry);
            }
        };
        ELFSymbolTable.prototype.getNumOfEntries = function () {
            return this.symTabEntries.length;
        };
        ELFSymbolTable.prototype.getRefSectionTable = function () {
            return this.sectionTable;
        };
        return ELFSymbolTable;
    })();
    ELFModel.ELFSymbolTable = ELFSymbolTable;
    /**
     * One entry inside a ELF note table
     */
    var ELFNoteTableEntry = (function () {
        function ELFNoteTableEntry(nameElement, noteName, type, descElement, noteDesc) {
            var _this = this;
            this.NameElement = nameElement;
            this.noteName = noteName;
            this.Type = type;
            this.noteDesc = noteDesc;
            this.DescElement = descElement;
            this.NameElement.description = function () { return _this.getName(); };
        }
        ELFNoteTableEntry.prototype.getName = function () {
            return this.noteName;
        };
        ELFNoteTableEntry.prototype.getDesc = function () {
            return this.noteDesc;
        };
        return ELFNoteTableEntry;
    })();
    ELFModel.ELFNoteTableEntry = ELFNoteTableEntry;
    /**
     * ELF note table
     */
    var ELFNoteTable = (function () {
        function ELFNoteTable(sectionTable, fileAccess, elfFile) {
            this.FA = fileAccess;
            this.sectionTable = sectionTable;
            this.elfFile = elfFile;
        }
        ELFNoteTable.prototype.load = function () {
            this.noteTabEntries = [];
            var result = ELFFileLoadResult.OK;
            var curOff = this.sectionTable.Sh_Offset.Get32BitValue();
            while (curOff + 0x18 <= this.sectionTable.Sh_Offset.Get32BitValue() + this.sectionTable.Sh_Size.Get32BitValue()) {
                var namesz = new ELFElement(this.FA, curOff, 4);
                curOff += 4;
                var descsz = new ELFElement(this.FA, curOff, 4);
                curOff += 4;
                var type = new ELFElement(this.FA, curOff, 4);
                curOff += 4;
                var noteName = "";
                if (namesz.Get32BitValue() > 0) {
                    if (curOff + namesz.Get32BitValue() > this.FA.getDataView().byteLength) {
                        result = ELFFileLoadResult.INVALID_ELF;
                        break;
                    }
                    noteName = this.FA.ReadByteString(curOff, namesz.Get32BitValue());
                    curOff += namesz.Get32BitValue();
                    var namePaddingVal = namesz.Get32BitValue();
                    while ((namePaddingVal & 0x03) != 0) {
                        curOff++;
                        namePaddingVal++;
                    }
                }
                var noteDesc = [];
                if (descsz.Get32BitValue() > 0) {
                    for (var i = 0; i < descsz.Get32BitValue(); i++) {
                        if (curOff > this.FA.getDataView().byteLength) {
                            result = ELFFileLoadResult.INVALID_ELF;
                            break;
                        }
                        noteDesc.push(this.FA.getDataView().getUint8(curOff));
                        curOff++;
                    }
                    var descPaddingVal = descsz.Get32BitValue();
                    while ((descPaddingVal & 0x03) != 0) {
                        curOff++;
                        descPaddingVal++;
                    }
                }
                this.noteTabEntries.push(new ELFNoteTableEntry(namesz, noteName, type, descsz, noteDesc));
            }
            return result;
        };
        ELFNoteTable.prototype.getNumOfEntries = function () {
            return this.noteTabEntries.length;
        };
        ELFNoteTable.prototype.getRefSectionTable = function () {
            return this.sectionTable;
        };
        return ELFNoteTable;
    })();
    ELFModel.ELFNoteTable = ELFNoteTable;
    /**
     * Main class to load and access the contents of a ELF file.
     */
    var ELFFile = (function () {
        function ELFFile(fileBytes) {
            this.elfProgramHeaderTables = [];
            this.elfSectionHeaderTables = [];
            this.elfSymbolTables = [];
            this.elfNoteTables = [];
            this.elfFileAccess = new ELFFileAccess(fileBytes);
            this.elfCompactMode = false;
        }
        ELFFile.prototype.loadProgramHeaderTables = function () {
            /* NOTE: following code only works with 32bit ELF files */
            if (((this.elfHeader.E_PhOff.value == 0) && (this.elfHeader.E_PhOff.value2 == 0)) ||
                ((this.elfHeader.E_PhOff.Get32BitValue() + (this.elfHeader.E_Phnum.Get32BitValue() * this.elfHeader.E_Phentsize.Get32BitValue())) > this.elfFileAccess.getDataView().byteLength)) {
                return ELFFileLoadResult.INVALID_ELF;
            }
            for (var headerIndex = 0; headerIndex < this.elfHeader.E_Phnum.Get32BitValue(); headerIndex++) {
                this.elfProgramHeaderTables.push(new ELFProgramHeaderTable(this, headerIndex, this.elfFileAccess));
                this.elfProgramHeaderTables[headerIndex].load(this.elfHeader.E_PhOff.Get32BitValue() + headerIndex * this.elfHeader.E_Phentsize.Get32BitValue(), this.elfHeader);
            }
            return ELFFileLoadResult.OK;
        };
        ELFFile.prototype.loadSectionHeaderTables = function () {
            /* NOTE: following code only works with 32bit ELF files */
            if (((this.elfHeader.E_ShOff.value == 0) && (this.elfHeader.E_ShOff.value2 == 0)) ||
                ((this.elfHeader.E_ShOff.Get32BitValue() + (this.elfHeader.E_Shnum.Get32BitValue() * this.elfHeader.E_Shentsize.Get32BitValue())) > this.elfFileAccess.getDataView().byteLength)) {
                return ELFFileLoadResult.INVALID_ELF;
            }
            for (var headerIndex = 0; headerIndex < this.elfHeader.E_Shnum.Get32BitValue(); headerIndex++) {
                this.elfSectionHeaderTables.push(new ELFSectionHeaderTable(headerIndex, this.elfFileAccess, this));
                this.elfSectionHeaderTables[headerIndex].load(this.elfHeader.E_ShOff.Get32BitValue() + headerIndex * this.elfHeader.E_Shentsize.Get32BitValue());
            }
            return ELFFileLoadResult.OK;
        };
        ELFFile.prototype.loadSymbolTables = function () {
            for (var secIdx = 0; secIdx < this.getNumOfSectionHeaderTables(); secIdx++) {
                if ((this.elfSectionHeaderTables[secIdx].Sh_Type.Get32BitValue() == ELFSectionHeaderTable.SHT_SYMTAB) ||
                    (this.elfSectionHeaderTables[secIdx].Sh_Type.Get32BitValue() == ELFSectionHeaderTable.SHT_DYNSYM)) {
                    var symTab = new ELFSymbolTable(this.elfSectionHeaderTables[secIdx], this.elfFileAccess, this);
                    symTab.load();
                    this.elfSymbolTables.push(symTab);
                }
            }
            return ELFFileLoadResult.OK;
        };
        ELFFile.prototype.loadNoteTables = function () {
            var result = ELFFileLoadResult.OK;
            for (var secIdx = 0; secIdx < this.getNumOfSectionHeaderTables(); secIdx++) {
                if (this.elfSectionHeaderTables[secIdx].Sh_Type.Get32BitValue() == ELFSectionHeaderTable.SHT_NOTE) {
                    var noteTab = new ELFNoteTable(this.elfSectionHeaderTables[secIdx], this.elfFileAccess, this);
                    result = noteTab.load();
                    if (result != ELFFileLoadResult.OK) {
                        break;
                    }
                    this.elfNoteTables.push(noteTab);
                }
            }
            return result;
        };
        ELFFile.prototype.getNumOfProgramHeaderTables = function () {
            return this.elfHeader.E_Phnum.Get32BitValue();
        };
        ELFFile.prototype.getNumOfSectionHeaderTables = function () {
            return this.elfHeader.E_Shnum.Get32BitValue();
        };
        ELFFile.prototype.getNumOfSymbolTables = function () {
            return this.elfSymbolTables.length;
        };
        ELFFile.prototype.getNumOfNoteTables = function () {
            return this.elfNoteTables.length;
        };
        ELFFile.prototype.load = function () {
            this.elfHeader = new ELFHeader(this.elfFileAccess);
            var result;
            result = this.elfHeader.load();
            if (result == ELFFileLoadResult.OK) {
                result = this.loadProgramHeaderTables();
            }
            if (result == ELFFileLoadResult.OK) {
                result = this.loadSectionHeaderTables();
            }
            if (result == ELFFileLoadResult.OK) {
                result = this.loadSymbolTables();
            }
            if (result == ELFFileLoadResult.OK) {
                result = this.loadNoteTables();
            }
            return result;
        };
        return ELFFile;
    })();
    ELFModel.ELFFile = ELFFile;
})(ELFModel || (ELFModel = {}));
//# sourceMappingURL=elf.js.map'use strict';

// ──────────────────────────────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────────────────────────────
const CONSTANTS = {
  PREVIEW_CONTEXT_SIZE: 100,
  HEX_CONTEXT_LINES: 20,
  BASE64_CHUNK_SIZE: 8192,
  MAX_CANVAS_PIXELS: 200_000_000,
  MAX_STORAGE_SIZE: 5 * 1024 * 1024,
  MAX_FILE_SIZE: 500 * 1024 * 1024,  // 500MB hard limit
  WARN_FILE_SIZE: 50 * 1024 * 1024,  // 50MB warning threshold
  DEBOUNCE_DELAY: 500,
  SCROLL_MARGIN: 10,
  SMOOTH_SCROLL_MAX: 10
};

// ──────────────────────────────────────────────────────────────────────
// ELF Detection
// ──────────────────────────────────────────────────────────────────────
function detectELFFormat(bytes) {
  if (!bytes || bytes.length < 52) return null;
  
  if (bytes[0] !== 0x7F || bytes[1] !== 0x45 || bytes[2] !== 0x4C || bytes[3] !== 0x46) {
    return null;
  }
  
  const elfClass = bytes[4] === 1 ? '32-bit' : bytes[4] === 2 ? '64-bit' : 'unknown';
  const elfData = bytes[5] === 1 ? 'LE' : bytes[5] === 2 ? 'BE' : 'unknown';
  
  console.log('✓ ELF detected:', elfClass, elfData);
  
  return {
    isELF: true,
    class: elfClass,
    endian: elfData,
    classValue: bytes[4],
    dataValue: bytes[5]
  };
}

// ──────────────────────────────────────────────────────────────────────
// State
// ──────────────────────────────────────────────────────────────────────
const appState = {
  fileData: null,
  canvasWidth: 1024,
  colorMode: 'hsv',
  canvasZoom: 5.0,
  zoomSensitivity: 30.0,
  selectedByteIdx: -1,
  statusLinesContext: 20,
  hexViewOverride: true,
  showCrosshair: true,
  cachedStorageSize: null,
  currentFileLoadToken: null,
  elfInfo: null,
  elfStructure: null,
  sectionOverlays: []
};

// Legacy global aliases for backward compatibility (will be removed gradually)
let fileData, canvasWidth, colorMode, canvasZoom, zoomSensitivity, selectedByteIdx;
let statusLinesContext, hexViewOverride, showCrosshair, cachedStorageSize, currentFileLoadToken;

function syncGlobals() {
  fileData = appState.fileData;
  canvasWidth = appState.canvasWidth;
  colorMode = appState.colorMode;
  canvasZoom = appState.canvasZoom;
  zoomSensitivity = appState.zoomSensitivity;
  selectedByteIdx = appState.selectedByteIdx;
  statusLinesContext = appState.statusLinesContext;
  hexViewOverride = appState.hexViewOverride;
  showCrosshair = appState.showCrosshair;
  cachedStorageSize = appState.cachedStorageSize;
  currentFileLoadToken = appState.currentFileLoadToken;
}

function syncState() {
  appState.fileData = fileData;
  appState.canvasWidth = canvasWidth;
  appState.colorMode = colorMode;
  appState.canvasZoom = canvasZoom;
  appState.zoomSensitivity = zoomSensitivity;
  appState.selectedByteIdx = selectedByteIdx;
  appState.statusLinesContext = statusLinesContext;
  appState.hexViewOverride = hexViewOverride;
  appState.showCrosshair = showCrosshair;
  appState.cachedStorageSize = cachedStorageSize;
  appState.currentFileLoadToken = currentFileLoadToken;
}

syncGlobals();

const canvas = document.getElementById('canvas');
const ctx = canvas.getContext('2d', { alpha: false, desynchronized: true });
const pixelMarker = document.getElementById('pixelMarker');
const crosshairH = document.getElementById('crosshairH');
const crosshairV = document.getElementById('crosshairV');
const hexCrosshairH = document.getElementById('hexCrosshairH');
const hexCrosshairV = document.getElementById('hexCrosshairV');

const dropzone = document.getElementById('dropzone');
const status = document.getElementById('status');
const statusContent = document.getElementById('statusContent');
const textPreview = document.getElementById('textPreview');
const widthInput = document.getElementById('widthInput');
const colorModeSelect = document.getElementById('colorMode');
const zoomLevelSlider = document.getElementById('zoomLevel');
const zoomLevelValue = document.getElementById('zoomLevelValue');
const zoomSensSlider = document.getElementById('zoomSensitivity');
const zoomSensValue = document.getElementById('zoomSensValue');
const hexViewCheckbox = document.getElementById('hexViewOverride');
const showCrosshairCheckbox = document.getElementById('showCrosshair');
const highlightSectionsCheckbox = document.getElementById('highlightSections');
const highlightSectionsLabel = document.getElementById('highlightSectionsLabel');
const blinkSectionsCheckbox = document.getElementById('blinkSections');
const blinkSectionsLabel = document.getElementById('blinkSectionsLabel');
const saveButton = document.getElementById('saveButton');

const fileName = document.getElementById('fileName');
const fileSize = document.getElementById('fileSize');
const lineCount = document.getElementById('lineCount');
const charCount = document.getElementById('charCount');
const renderTime = document.getElementById('renderTime');
const debugInfo = document.getElementById('debugInfo');
const elfInfo = document.getElementById('elfInfo');

// ──────────────────────────────────────────────────────────────────────
// Canvas transform utility
// ──────────────────────────────────────────────────────────────────────
function applyCanvasZoom(zoom) {
  canvas.style.transform = `scale(${zoom})`;
  canvas.style.transformOrigin = '0 0';
  
  // Update ELF overlays to match new zoom
  if (appState.elfStructure) {
    renderELFOverlays();
  }
}

function calculateZoomStep(sensitivity, multiplier = 1) {
  return 0.1 * (sensitivity / 10.0) * multiplier;
}

function hideHexCrosshairs() {
  hexCrosshairH.style.display = 'none';
  hexCrosshairV.style.display = 'none';
}

// ──────────────────────────────────────────────────────────────────────
// Calculate optimal canvas width based on file size
// Aims to keep ImageData memory reasonable and prevent browser crashes
// ──────────────────────────────────────────────────────────────────────
function calculateOptimalWidth(fileSize) {
  // Safe widths based on actual rendering tests
  
  if (fileSize <= 1024 * 1024) {          // < 1MB
    return Math.max(64, Math.min(1024, Math.floor(Math.sqrt(fileSize))));
  } else if (fileSize <= 10 * 1024 * 1024) {  // 1-10MB
    return 1024;
  } else if (fileSize <= 50 * 1024 * 1024) {  // 10-50MB  
    return 1536;
  } else if (fileSize <= 100 * 1024 * 1024) { // 50-100MB
    return 2048;
  } else if (fileSize <= 150 * 1024 * 1024) { // 100-150MB
    return 4096;
  } else if (fileSize <= 200 * 1024 * 1024) { // 150-200MB
    return 8192;// failsafe than 2944;  // Empirically safe for 190MB files
  } else if (fileSize <= 222 * 1024 * 1024) { // 222MB
    // For very large files, use power of 2 close to size^0.45
    const target = Math.pow(fileSize, 0.45);
    return Math.pow(2, Math.floor(Math.log2(target)));
  } else {                                     // > 300MB
    // Maximum practical width: 16384 (power of 2)
    const target = Math.pow(fileSize, 0.42);
    return Math.min(16384, Math.pow(2, Math.floor(Math.log2(target))));
  }
}

// ──────────────────────────────────────────────────────────────────────
// HSV → RGB conversion (same as Python)
// ──────────────────────────────────────────────────────────────────────
function hsvToRgb(h, s, v) {
  const i = Math.floor(h * 6) % 6;
  const f = (h * 6) - Math.floor(h * 6);
  const p = Math.floor(255 * v * (1 - s));
  const q = Math.floor(255 * v * (1 - f * s));
  const t = Math.floor(255 * v * (1 - (1 - f) * s));
  const v255 = Math.floor(255 * v);
  
  if (i === 0) return [v255, t, p];
  if (i === 1) return [q, v255, p];
  if (i === 2) return [p, v255, t];
  if (i === 3) return [p, q, v255];
  if (i === 4) return [t, p, v255];
  return [v255, p, q];
}

function hexToRgb(hex) {
  const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
  return result ? {
    r: parseInt(result[1], 16),
    g: parseInt(result[2], 16),
    b: parseInt(result[3], 16)
  } : { r: 255, g: 255, b: 255 };
}

// ──────────────────────────────────────────────────────────────────────
// File parsing (handles \n, \\, UTF-8)
// Build char-to-byte mapping from original raw bytes
// ──────────────────────────────────────────────────────────────────────
function parseFile(text, rawBytes) {
  const rawLines = text.split(/\r?\n/);
  const lines = [];
  const lineStarts = [0];
  const byteLineStarts = [0];
  let totalChars = 0;
  let byteOffset = 0;
  const decoder = new TextDecoder('utf-8', { fatal: false });
  
  for (let i = 0; i < rawLines.length; i++) {
    const s = rawLines[i];
    lines.push(s);
    totalChars += s.length;
    lineStarts.push(totalChars);
    
    // Find the actual byte length of this line in rawBytes
    // Scan forward from current byteOffset until we hit \n or end
    let lineByteLen = 0;
    while (byteOffset + lineByteLen < rawBytes.length) {
      if (rawBytes[byteOffset + lineByteLen] === 0x0A) { // \n
        lineByteLen++; // include the newline
        break;
      }
      lineByteLen++;
    }
    
    byteOffset += lineByteLen;
    byteLineStarts.push(byteOffset);
  }
  
  return { lines, lineStarts, byteLineStarts, totalChars };
}

// ──────────────────────────────────────────────────────────────────────
// GPU-accelerated rendering via ImageData
// Render from raw bytes directly to show ALL bytes including \r
// ──────────────────────────────────────────────────────────────────────
function renderThumbnail(width) {
  if (!fileData) return;
  
  const t0 = performance.now();
  const { rawBytes } = fileData;
  
  if (!rawBytes || rawBytes.length === 0) {
    canvas.width = width;
    canvas.height = 1;
    ctx.fillStyle = '#fff';
    ctx.fillRect(0, 0, width, 1);
    renderTime.textContent = '0 ms';
    return;
  }
  
  const totalBytes = rawBytes.length;
  const MAX_CANVAS_PIXELS = CONSTANTS.MAX_CANVAS_PIXELS;
  
  // Safety check: Warn if rendering might be slow/unstable
  const estimatedImageDataMB = (totalBytes * 4) / (1024 * 1024);
  if (estimatedImageDataMB > 300 && colorMode === 'hsv') {
    console.warn(`Large ImageData: ${estimatedImageDataMB.toFixed(0)}MB. HSV mode may be slow. Consider using Grayscale for initial render.`);
  }
  
  // Auto-adjust width if canvas would exceed pixel limit
  let adjustedWidth = width;
  let height = Math.ceil(totalBytes / adjustedWidth);
  
  if (adjustedWidth * height > MAX_CANVAS_PIXELS) {
    // Calculate maximum safe width for this file size
    adjustedWidth = Math.floor(Math.sqrt(totalBytes));
    // Round to nearest power of 2 for cleaner layout
    adjustedWidth = Math.pow(2, Math.floor(Math.log2(adjustedWidth)));
    height = Math.ceil(totalBytes / adjustedWidth);
    
    console.warn(`File too large for ${width}px width. Auto-adjusted to ${adjustedWidth}px (${adjustedWidth}×${height} = ${(adjustedWidth * height / 1_000_000).toFixed(1)}M pixels)`);
    statusContent.textContent = `⚠️ Large file: auto-adjusted width to ${adjustedWidth}px to avoid canvas limits`;
    
    // CRITICAL: global canvasWidth should == actual canvas
    canvasWidth = widthInput.value = adjustedWidth;
  }
  
  canvas.width = adjustedWidth;
  canvas.height = height;
  
  const imgData = ctx.createImageData(adjustedWidth, height);
  const data = imgData.data;
  
  // Build byte-to-section lookup for ELF files
  const elfSectionMap = new Map();
  if (appState.elfStructure && appState.sectionOverlays.length > 0) {
    appState.sectionOverlays.forEach(region => {
      for (let i = region.start; i < region.end; i++) {
        elfSectionMap.set(i, region);
      }
    });
  }
  
  for (let idx = 0; idx < totalBytes; idx++) {
    const val = rawBytes[idx];
    let r, g, b;
    
    // Check if byte is in an ELF section
    const elfSection = elfSectionMap.get(idx);
    
    if (elfSection && colorMode === 'hsv') {
      // Section-based coloring: tint with section color
      const hi = (val >> 4) & 0xF;
      const lo = val & 0xF;
      const h = hi / 16.0;
      const v = 0.35 + (lo / 15.0) * 0.6;
      [r, g, b] = hsvToRgb(h, 1.0, v);
      
      // Apply section color tint
      const tintColor = hexToRgb(elfSection.color);
      const tintStrength = 0.25;
      r = Math.floor(r * (1 - tintStrength) + tintColor.r * tintStrength);
      g = Math.floor(g * (1 - tintStrength) + tintColor.g * tintStrength);
      b = Math.floor(b * (1 - tintStrength) + tintColor.b * tintStrength);
    } else if (colorMode === 'hsv') {
      const hi = (val >> 4) & 0xF;
      const lo = val & 0xF;
      const h = hi / 16.0;
      const v = 0.35 + (lo / 15.0) * 0.6;
      [r, g, b] = hsvToRgb(h, 1.0, v);
    } else {
      const gval = 40 + Math.floor((val / 255.0) * 200);
      r = g = b = gval;
    }
    
    const row = Math.floor(idx / adjustedWidth);
    const col = idx % adjustedWidth;
    
    if (row < height) {
      const offset = (row * adjustedWidth + col) * 4;
      data[offset] = r;
      data[offset + 1] = g;
      data[offset + 2] = b;
      data[offset + 3] = 255;
    }
  }
  
  ctx.putImageData(imgData, 0, 0);
  
  // Apply zoom to canvas display
  applyCanvasZoom(canvasZoom);
  
  const elapsed = (performance.now() - t0).toFixed(1);
  renderTime.textContent = `${elapsed} ms`;
  
  // Update debugInfo with render stats
  if (adjustedWidth !== width) {
    debugInfo.innerHTML = `Rendered: ${adjustedWidth}×${height}<br>` +
                          `Adjusted from ${width}px<br>` +
                          `${totalBytes.toLocaleString()} bytes in ${elapsed}ms<br>` +
                          `Zoom: ${canvasZoom.toFixed(3)}× (${(canvasZoom * 100).toFixed(0)}%)`;
  } else {
    debugInfo.innerHTML = `Rendered: ${adjustedWidth}×${height}<br>` +
                          `${totalBytes.toLocaleString()} bytes in ${elapsed}ms<br>` +
                          `Zoom: ${canvasZoom.toFixed(3)}× (${(canvasZoom * 100).toFixed(0)}%)`;
  }
  
  // Update pixel marker position after rerender
  if (selectedByteIdx >= 0) {
    updatePixelMarker(selectedByteIdx);
  }
  
  // Render ELF section overlays
  renderELFOverlays();
}

// ──────────────────────────────────────────────────────────────────────
// Render ELF section overlays
// ──────────────────────────────────────────────────────────────────────
function renderELFOverlays() {
  const startTime = performance.now();
  
  // Clear existing overlays
  const existingOverlays = document.querySelectorAll('.elf-overlay');
  existingOverlays.forEach(el => el.remove());
  
  console.log(`[Overlay] Removed ${existingOverlays.length} existing overlays`);
  
  if (!appState.elfStructure || appState.sectionOverlays.length === 0) {
    return;
  }
  
  // Check if highlighting is enabled
  if (!highlightSectionsCheckbox.checked) {
    return;
  }
  
  const canvasContainer = canvas.parentElement;
  const width = canvasWidth;
  
  let overlayCount = 0;
  appState.sectionOverlays.forEach((region, idx) => {
    const { start, end, label, color } = region;
    
    // Calculate row/column positions
    const startRow = Math.floor(start / width);
    const startCol = start % width;
    const endRow = Math.floor((end - 1) / width);
    const endCol = (end - 1) % width;
    
    // Draw only perimeter borders using border segments
    const beforeCount = document.querySelectorAll('.elf-overlay').length;
    drawSectionPerimeter(canvasContainer, startRow, startCol, endRow, endCol, width, color, label, start, end);
    const afterCount = document.querySelectorAll('.elf-overlay').length;
    overlayCount += (afterCount - beforeCount);
  });
  
  const endTime = performance.now();
  console.log(`[Overlay] Created ${overlayCount} DOM elements for ${appState.sectionOverlays.length} sections in ${(endTime - startTime).toFixed(2)}ms`);
  console.log(`[Overlay] Average ${(overlayCount / appState.sectionOverlays.length).toFixed(1)} elements per section`);
}

function drawSectionPerimeter(container, startRow, startCol, endRow, endCol, width, color, label, sectionStart, sectionEnd) {
  const pixelSize = canvasZoom;
  
  // Top border
  if (startRow === endRow) {
    // Single row - simple rectangle
    createBorderSegment(container, startCol * pixelSize, startRow * pixelSize, 
                       (endCol - startCol + 1) * pixelSize, pixelSize, 
                       color, true, true, true, true, label, sectionStart, sectionEnd);
  } else {
    // Multiple rows - draw perimeter only
    
    // Top edge of first row
    createBorderSegment(container, startCol * pixelSize, startRow * pixelSize,
                       (width - startCol) * pixelSize, pixelSize,
                       color, true, true, false, startCol === 0, label, sectionStart, sectionEnd);
    
    // Left edge of middle rows
    if (startCol > 0) {
      for (let row = startRow + 1; row <= endRow; row++) {
        createBorderSegment(container, 0, row * pixelSize, startCol * pixelSize, pixelSize,
                           color, false, false, false, true, '', sectionStart, sectionEnd);
      }
    }
    
    // Right edge of middle rows (if first row doesn't reach end)
    for (let row = startRow + 1; row < endRow; row++) {
      createBorderSegment(container, 0, row * pixelSize, width * pixelSize, pixelSize,
                         color, false, true, false, startCol === 0, '', sectionStart, sectionEnd);
    }
    
    // Bottom edge of last row
    createBorderSegment(container, 0, endRow * pixelSize, (endCol + 1) * pixelSize, pixelSize,
                       color, false, endCol === width - 1, true, true, '', sectionStart, sectionEnd);
    
    // Right edge gap filler if needed
    if (endCol < width - 1) {
      for (let row = startRow + 1; row < endRow; row++) {
        createBorderSegment(container, (width - 1) * pixelSize, row * pixelSize, pixelSize, pixelSize,
                           color, false, true, false, false, '', sectionStart, sectionEnd);
      }
    }
  }
}

function createBorderSegment(container, left, top, width, height, color, 
                             borderTop, borderRight, borderBottom, borderLeft,
                             label, sectionStart, sectionEnd) {
  const overlay = document.createElement('div');
  overlay.className = 'elf-overlay';
  overlay.style.position = 'absolute';
  overlay.style.pointerEvents = 'none';
  overlay.style.zIndex = '5';
  
  overlay.style.left = left + 'px';
  overlay.style.top = top + 'px';
  overlay.style.width = width + 'px';
  overlay.style.height = height + 'px';
  overlay.style.background = 'transparent';
  overlay.style.boxSizing = 'border-box';
  
  // Only animate if blink is enabled
  if (blinkSectionsCheckbox.checked) {
    overlay.style.animation = 'sectionBlink 0.5s ease-in-out infinite';
  } else {
    overlay.style.animation = 'none';
  }
  
  // Use box-shadow inset borders to prevent overlap with adjacent sections
  const shadows = [];
  const borderSize = 1; // Use 1px inset shadows
  
  if (borderTop) {
    shadows.push(`inset 0 ${borderSize}px 0 0 ${color}`);
  }
  if (borderRight) {
    shadows.push(`inset -${borderSize}px 0 0 0 ${color}`);
  }
  if (borderBottom) {
    shadows.push(`inset 0 -${borderSize}px 0 0 ${color}`);
  }
  if (borderLeft) {
    shadows.push(`inset ${borderSize}px 0 0 0 ${color}`);
  }
  
  if (shadows.length > 0) {
    overlay.style.boxShadow = shadows.join(', ');
  }
  
  // Add label and tooltip
  if (label) {
    overlay.title = `${label}\n0x${sectionStart.toString(16).toUpperCase()} - 0x${sectionEnd.toString(16).toUpperCase()}\nSize: ${formatBytes(sectionEnd - sectionStart)}`;
    overlay.style.cursor = 'help';
  }
  
  container.appendChild(overlay);
}

// ──────────────────────────────────────────────────────────────────────
// Render ELF info panel
// ──────────────────────────────────────────────────────────────────────
function renderELFInfoPanel() {
  if (!appState.elfStructure || appState.sectionOverlays.length === 0) {
    elfInfo.style.display = 'none';
    return;
  }
  
  elfInfo.style.display = 'flex';
  
  const elf = appState.elfStructure;
  const header = elf.elfHeader;
  
  let html = '<div class="elf-header-wrapper">';
  
  // Header info - compact 2-column layout (no title)
  html += '<div class="elf-header-info">';
  html += `<span><strong>Structure:</strong> ELF ${header.E_ident_class.description()}</span>`;
  html += `<span><strong>Machine:</strong> ${header.E_machine.description()}</span>`;
  html += `<span><strong>Type:</strong> ${header.E_type.description()}</span>`;
  html += `<span><strong>Entry Point:</strong> ${header.E_Entry.GetHexValueStr(8)}</span>`;
  html += '</div>';
  
  // Section list header
  html += '<div class="elf-section elf-section-header">';
  html += '<div></div>';
  html += '<div>Offset</div>';
  html += '<div>Bytes</div>';
  html += '<div>Size</div>';
  html += '<div>End</div>';
  html += '<div>Name</div>';
  html += '</div>';
  html += '</div>'; // Close elf-header-wrapper
  
  // Scrollable sections list
  html += '<div class="elf-sections-wrapper">';
  
  // Sections
  appState.sectionOverlays.forEach((region, idx) => {
    const { start, end, label, color } = region;
    const size = end - start;
    
    html += `<div class="elf-section" data-section-idx="${idx}" data-section-start="${start}" data-section-end="${end}">`;
    html += `<div><span class="color-indicator" style="background:${color};"></span></div>`;
    html += `<div>0x${start.toString(16).toUpperCase().padStart(8, '0')}</div>`;
    html += `<div>${size.toLocaleString()}</div>`;
    html += `<div>${formatBytes(size)}</div>`;
    html += `<div>0x${end.toString(16).toUpperCase().padStart(8, '0')}</div>`;
    html += `<div>${escapeHtml(label)}</div>`;
    html += '</div>';
  });
  
  html += '</div>'; // Close elf-sections-wrapper
  
  elfInfo.innerHTML = html;
  
  // Add click handlers to sections
  const sectionElements = elfInfo.querySelectorAll('.elf-section[data-section-idx]');
  sectionElements.forEach(el => {
    el.addEventListener('click', () => {
      const sectionIdx = parseInt(el.getAttribute('data-section-idx'));
      const sectionStart = parseInt(el.getAttribute('data-section-start'));
      
      // Highlight section in list
      highlightELFSection(sectionIdx);
      
      // Select first byte of section on canvas
      displayBytePreview(sectionStart);
    });
  });
}

// ──────────────────────────────────────────────────────────────────────
// Highlight ELF section in info panel
// ──────────────────────────────────────────────────────────────────────
function highlightELFSection(sectionIdx) {
  // Remove previous selection
  const prevSelected = elfInfo.querySelectorAll('.elf-section.selected');
  prevSelected.forEach(el => el.classList.remove('selected'));
  
  // Add selection to target section
  const targetSection = elfInfo.querySelector(`.elf-section[data-section-idx="${sectionIdx}"]`);
  if (targetSection) {
    targetSection.classList.add('selected');
    
    // Scroll into view if needed
    targetSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
}

// ──────────────────────────────────────────────────────────────────────
// Find which ELF section contains a byte offset
// ──────────────────────────────────────────────────────────────────────
function findSectionByByteOffset(byteOffset) {
  if (!appState.sectionOverlays || appState.sectionOverlays.length === 0) {
    return -1;
  }
  
  for (let i = 0; i < appState.sectionOverlays.length; i++) {
    const { start, end } = appState.sectionOverlays[i];
    if (byteOffset >= start && byteOffset < end) {
      return i;
    }
  }
  
  return -1;
}

// ──────────────────────────────────────────────────────────────────────
// Binary search to find line by char index
// ──────────────────────────────────────────────────────────────────────
function findLine(charIdx) {
  if (!fileData) return -1;
  const { lineStarts, totalChars } = fileData;
  if (charIdx < 0 || charIdx >= totalChars) return -1;
  
  let lo = 0, hi = lineStarts.length - 1;
  while (lo < hi) {
    const mid = Math.floor((lo + hi + 1) / 2);
    if (lineStarts[mid] <= charIdx) lo = mid;
    else hi = mid - 1;
  }
  return lo;
}

// ──────────────────────────────────────────────────────────────────────
// Convert character index to byte offset
// Walk through actual raw bytes to find UTF-8 character boundaries
// ──────────────────────────────────────────────────────────────────────
function charIndexToByteOffset(charIdx) {
  if (!fileData) return -1;
  const { lines, lineStarts, byteLineStarts, rawBytes } = fileData;
  if (charIdx < 0 || charIdx >= fileData.totalChars) return -1;
  
  // Find which line the character is on
  const lineNum = findLine(charIdx);
  if (lineNum < 0) return -1;
  
  // Get character position within the line
  const charOffsetInLine = charIdx - lineStarts[lineNum];
  
  // Get the byte position of the line start
  const lineByteStart = byteLineStarts[lineNum];
  
  // Walk through the raw bytes to count UTF-8 characters
  let bytePos = lineByteStart;
  let charCount = 0;
  const decoder = new TextDecoder('utf-8', { fatal: false });
  
  while (bytePos < rawBytes.length && charCount < charOffsetInLine) {
    const byte = rawBytes[bytePos];
    
    // Detect UTF-8 character length by first byte
    let charByteLen = 1;
    if ((byte & 0x80) === 0) {
      // ASCII: 0xxxxxxx
      charByteLen = 1;
    } else if ((byte & 0xE0) === 0xC0) {
      // 2-byte: 110xxxxx
      charByteLen = 2;
    } else if ((byte & 0xF0) === 0xE0) {
      // 3-byte: 1110xxxx
      charByteLen = 3;
    } else if ((byte & 0xF8) === 0xF0) {
      // 4-byte: 11110xxx
      charByteLen = 4;
    } else {
      // Invalid UTF-8 start byte, decoder will make it one replacement char
      charByteLen = 1;
    }
    
    // Check if this is a valid UTF-8 sequence
    let validSequence = true;
    if (charByteLen > 1) {
      for (let i = 1; i < charByteLen; i++) {
        if (bytePos + i >= rawBytes.length || (rawBytes[bytePos + i] & 0xC0) !== 0x80) {
          validSequence = false;
          break;
        }
      }
    }
    
    if (!validSequence && charByteLen > 1) {
      // Invalid sequence, treat as single byte replacement char
      bytePos++;
      charCount++;
    } else {
      bytePos += charByteLen;
      charCount++;
    }
    
    // Stop at newline
    if (rawBytes[bytePos - 1] === 0x0A) break;
  }
  
  return bytePos;
}

// ──────────────────────────────────────────────────────────────────────
// Update pixel marker position on canvas
// ──────────────────────────────────────────────────────────────────────
function updatePixelMarker(byteIdx) {
  if (!fileData || !fileData.rawBytes || byteIdx < 0 || byteIdx > fileData.rawBytes.length - 1) {
    pixelMarker.style.display = 'none';
    crosshairH.style.display = 'none';
    crosshairV.style.display = 'none';
    debugInfo.innerHTML = '—';
    return;
  }
  
  const row = Math.floor(byteIdx / canvasWidth);
  const col = byteIdx % canvasWidth;
  
  // Position relative to scaled canvas - use exact pixel boundaries
  // Use floor to ensure we start at exact pixel boundary
  const scaledX = Math.floor(col * canvasZoom);
  const scaledY = Math.floor(row * canvasZoom);
  const scaledWidth = Math.ceil((col + 1) * canvasZoom) - scaledX;
  const scaledHeight = Math.ceil((row + 1) * canvasZoom) - scaledY;
  
  pixelMarker.style.cssText = `display:block;left:${scaledX}px;top:${scaledY}px;width:${scaledWidth}px;height:${scaledHeight}px;`;
  
  // Scroll into view if pixel is outside viewport
  const wrap = document.getElementById('canvasWrap');
  const margin = CONSTANTS.SCROLL_MARGIN;
  const pixelLeft = scaledX;
  const pixelTop = scaledY;
  const pixelRight = scaledX + scaledWidth;
  const pixelBottom = scaledY + scaledHeight;
  
  const viewWidth = wrap.clientWidth;
  const viewHeight = wrap.clientHeight;
  
  // Get current scroll position
  let scrollLeft = wrap.scrollLeft;
  let scrollTop = wrap.scrollTop;
  
  // Check if pixel is completely outside viewport (wrapping case)
  const isOutsideLeft = pixelRight < scrollLeft;
  const isOutsideRight = pixelLeft > scrollLeft + viewWidth;
  const isOutsideTop = pixelBottom < scrollTop;
  const isOutsideBottom = pixelTop > scrollTop + viewHeight;
  
  if (isOutsideLeft || isOutsideRight || isOutsideTop || isOutsideBottom) {
    // Large jump (wrap) - scroll to show pixel with margin
    wrap.scrollLeft = Math.max(0, pixelLeft - margin);
    wrap.scrollTop = Math.max(0, pixelTop - margin);
  } else {
    // Smooth scroll: only when within margin of edge, move max 10px
    const leftEdge = scrollLeft + margin;
    const rightEdge = scrollLeft + viewWidth - margin;
    
    if (pixelLeft < leftEdge && pixelLeft >= 0) {
      const scrollAmount = Math.min(CONSTANTS.SMOOTH_SCROLL_MAX, leftEdge - pixelLeft);
      wrap.scrollLeft = Math.max(0, scrollLeft - scrollAmount);
    } else if (pixelRight > rightEdge) {
      const scrollAmount = Math.min(CONSTANTS.SMOOTH_SCROLL_MAX, pixelRight - rightEdge);
      wrap.scrollLeft = scrollLeft + scrollAmount;
    }
    
    const topEdge = scrollTop + margin;
    const bottomEdge = scrollTop + viewHeight - margin;
    
    if (pixelTop < topEdge && pixelTop >= 0) {
      const scrollAmount = Math.min(CONSTANTS.SMOOTH_SCROLL_MAX, topEdge - pixelTop);
      wrap.scrollTop = Math.max(0, scrollTop - scrollAmount);
    } else if (pixelBottom > bottomEdge) {
      const scrollAmount = Math.min(CONSTANTS.SMOOTH_SCROLL_MAX, pixelBottom - bottomEdge);
      wrap.scrollTop = scrollTop + scrollAmount;
    }
  }
  
  // Get actual canvas dimensions (used by crosshairs and debug info)
  const canvasDisplayWidth = canvas.width * canvasZoom;
  const canvasDisplayHeight = canvas.height * canvasZoom;
  
  // Update crosshair position (show when enabled)
  if (showCrosshair) {
    //Reduce reflows from 11 to 3 per marker update
    crosshairH.style.cssText = `display:block;left:0;width:${canvasDisplayWidth}px;top:${scaledY}px;height:${scaledHeight}px;`;
    crosshairV.style.cssText = `display:block;top:0;height:${canvasDisplayHeight}px;left:${scaledX}px;width:${scaledWidth}px;`;
  } else {
    crosshairH.style.display = 'none';
    crosshairV.style.display = 'none';
  }
  
  // Update debug info
  const x2 = scaledX + scaledWidth;
  const y2 = scaledY + scaledHeight;
  
  debugInfo.innerHTML = `Pixel: (${col}, ${row})<br>` +
                        `Zoom: ${canvasZoom.toFixed(3)}× (${(canvasZoom * 100).toFixed(0)}%)<br>` +
                        `HorizontalLine: 0,${scaledY}-${Math.round(canvasDisplayWidth)},${y2}<br>` +
                        `VerticalLine: ${scaledX},0-${x2},${Math.round(canvasDisplayHeight)}`;
}

// ──────────────────────────────────────────────────────────────────────
// Byte-to-display conversion (UTF-8 aware)
// ──────────────────────────────────────────────────────────────────────
function buildByteDisplay(rawBytes, startIdx, endIdx) {
  let result = '';
  let i = startIdx;
  
  while (i < endIdx) {
    const byte = rawBytes[i];
    
    // Fast path for common cases
    if (byte >= 32 && byte < 127) {
      result += String.fromCharCode(byte);
      i++;
    } else if (byte === 0x20) {
      result += ' ';
      i++;
    } else if (byte < 32 || byte === 127) {
      // Control characters
      if (byte === 0x00) result += '␀';
      else if (byte === 0x09) result += '␉';
      else if (byte === 0x0A) result += '␊';
      else if (byte === 0x0D) result += '␍';
      else result += (byte % 2 === 0) ? '☺' : '☻';
      i++;
    } else {
      // UTF-8 multi-byte sequence
      let seqLen = 1;
      if ((byte & 0xE0) === 0xC0) seqLen = 2;
      else if ((byte & 0xF0) === 0xE0) seqLen = 3;
      else if ((byte & 0xF8) === 0xF0) seqLen = 4;
      
      const decoder = new TextDecoder('utf-8', { fatal: false });
      const seqBytes = rawBytes.slice(i, Math.min(i + seqLen, endIdx));
      result += decoder.decode(seqBytes);
      i += seqLen;
    }
  }
  
  return result;
}

// ──────────────────────────────────────────────────────────────────────
// Generate text preview with context
// ──────────────────────────────────────────────────────────────────────
function generateTextPreview(rawBytes, byteOffset, contextSize = CONSTANTS.PREVIEW_CONTEXT_SIZE) {
  const startByte = Math.max(0, byteOffset - contextSize);
  const endByte = Math.min(rawBytes.length, byteOffset + contextSize + 1);
  
  const beforeDisplay = buildByteDisplay(rawBytes, startByte, byteOffset);
  const selectedSymbol = buildByteDisplay(rawBytes, byteOffset, byteOffset + 1) || '?';
  const afterDisplay = buildByteDisplay(rawBytes, byteOffset + 1, endByte);
  
  const leftEllipsis = startByte > 0 ? '… ' : '';
  const rightEllipsis = endByte < rawBytes.length ? ' …' : '';
  
  const textColor = '#00ffff';
  const backColor = '#ff0000';
  
  return `${leftEllipsis}${escapeHtml(beforeDisplay)}<span style="background:${backColor};color:${textColor}!important;font-weight:bold">${escapeHtml(selectedSymbol)}</span>${escapeHtml(afterDisplay)}${rightEllipsis}`;
}

// ──────────────────────────────────────────────────────────────────────
// Update text preview display
// ──────────────────────────────────────────────────────────────────────
function updateTextPreview(name, byteOffset, preview) {
  textPreview.innerHTML = `<span style="background:#000">${escapeHtml(name)}:byte=${byteOffset} (0x${byteOffset.toString(16)}): ${preview}</span>`;
  textPreview.style.display = 'block';
}

// ──────────────────────────────────────────────────────────────────────
// Update hex view display
// ──────────────────────────────────────────────────────────────────────
// Track last hex view context to avoid unnecessary regeneration
updateHexView.lastCenterByte = -1;
updateHexView.lastContextLines = -1;

function updateHexView(name, rawBytes, byteOffset) {
  if (!rawBytes) {
    statusContent.textContent = 'No raw bytes available';
    hideHexCrosshairs();
    updateHexView.lastCenterByte = -1;
    return;
  }
  
  if (byteOffset < 0 || byteOffset >= rawBytes.length) {
    statusContent.textContent = `Byte offset out of range: ${byteOffset}`;
    hideHexCrosshairs();
    return;
  }
  
  const bytesPerLine = 16;
  const clickedLine = Math.floor(byteOffset / bytesPerLine);
  
  // Check if we need to regenerate the hex view context window
  // Only regenerate if the clicked byte is outside ~70% of the current context window
  let centerByte;
  const shouldRegenerate = updateHexView.lastCenterByte === -1 
    || updateHexView.lastContextLines !== statusLinesContext
    || Math.abs(Math.floor(updateHexView.lastCenterByte / bytesPerLine) - clickedLine) > Math.floor(statusLinesContext * 0.7);
  
  if (shouldRegenerate) {
    centerByte = byteOffset;
    updateHexView.lastCenterByte = byteOffset;
    updateHexView.lastContextLines = statusLinesContext;
  } else {
    // Keep the same center, just update the highlighting
    centerByte = updateHexView.lastCenterByte;
  }
  
  const byteValue = rawBytes[byteOffset];
  const hexVal = byteValue.toString(16).padStart(2, '0');
  const preview = formatHexdump(rawBytes, 0, centerByte, statusLinesContext, showCrosshair, byteOffset);
  statusContent.innerHTML = `<div style="background:#000;font-family:monospace;white-space:pre;color:#eee">${escapeHtml(name)}:byte=0x${byteOffset.toString(16).padStart(8,'0')} (${byteOffset}d):0x${hexVal}:\n${preview}</div>`;
  
  hideHexCrosshairs();
}

// ──────────────────────────────────────────────────────────────────────
// Display selected byte preview (orchestrator)
// ──────────────────────────────────────────────────────────────────────
function displayBytePreview(byteIdx) {
  if (!fileData || !fileData.rawBytes || byteIdx < 0 || byteIdx >= fileData.rawBytes.length) return;
  
  selectedByteIdx = byteIdx;
  updatePixelMarker(byteIdx);
  
  // Debounce saves during navigation
  if (displayBytePreview.saveTimeout) {
    clearTimeout(displayBytePreview.saveTimeout);
    displayBytePreview.saveTimeout = null;
  }
  displayBytePreview.saveTimeout = setTimeout(() => {
    displayBytePreview.saveTimeout = null;
    saveFileToStorage();
  }, CONSTANTS.DEBOUNCE_DELAY);
  
  const textPreviewContent = generateTextPreview(fileData.rawBytes, byteIdx);
  updateTextPreview(fileData.name, byteIdx, textPreviewContent);
  updateHexView(fileData.name, fileData.rawBytes, byteIdx);
}

// ──────────────────────────────────────────────────────────────────────
// Click handler: show first 100 + last 100 chars
// ──────────────────────────────────────────────────────────────────────
canvas.addEventListener('click', (ev) => {
  if (!fileData) return;
  
  const rect = canvas.getBoundingClientRect();
  const relX = ev.clientX - rect.left;
  const relY = ev.clientY - rect.top;
  
  if (relX < 0 || relY < 0 || relX >= rect.width || relY >= rect.height) return;
  
  const x = Math.floor(relX * canvas.width / rect.width);
  const y = Math.floor(relY * canvas.height / rect.height);
  const byteIdx = y * canvas.width + x;
  
  displayBytePreview(byteIdx);
  
  // If ELF format detected, highlight corresponding section
  if (appState.elfStructure) {
    const sectionIdx = findSectionByByteOffset(byteIdx);
    if (sectionIdx >= 0) {
      highlightELFSection(sectionIdx);
    }
  }
});

// ──────────────────────────────────────────────────────────────────────
// Canvas zoom with proper origin tracking
// ──────────────────────────────────────────────────────────────────────
let zoomOriginX = 0;
let zoomOriginY = 0;
let pendingZoomUpdate = null;

function updateCanvasZoom(newZoom, clientX, clientY) {
  const wrap = document.getElementById('canvasWrap');
  const wrapRect = wrap.getBoundingClientRect();
  
  // Calculate pointer position relative to viewport
  const viewportX = clientX - wrapRect.left;
  const viewportY = clientY - wrapRect.top;
  
  // Get current scroll positions
  const scrollLeft = wrap.scrollLeft;
  const scrollTop = wrap.scrollTop;
  
  // Calculate position in original (unscaled) canvas coordinates
  const canvasX = (scrollLeft + viewportX) / canvasZoom;
  const canvasY = (scrollTop + viewportY) / canvasZoom;
  
  // Update zoom
  const oldZoom = canvasZoom;
  canvasZoom = Math.max(0.1, Math.min(30, newZoom));
  applyCanvasZoom(canvasZoom);
  
  // Update zoom slider and display
  zoomLevelSlider.value = canvasZoom;
  zoomLevelValue.textContent = canvasZoom.toFixed(1);
  
  // Update debugInfo if it exists
  if (fileData && fileData.rawBytes) {
    const currentDebug = debugInfo.innerHTML;
    // Update only the zoom line if debugInfo has content
    if (currentDebug && currentDebug !== '—') {
      const lines = currentDebug.split('<br>');
      // Find and update zoom line, or append it
      let found = false;
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].startsWith('Zoom:')) {
          lines[i] = `Zoom: ${canvasZoom.toFixed(3)}× (${(canvasZoom * 100).toFixed(0)}%)`;
          found = true;
          break;
        }
      }
      if (!found) {
        lines.push(`Zoom: ${canvasZoom.toFixed(3)}× (${(canvasZoom * 100).toFixed(0)}%)`);
      }
      debugInfo.innerHTML = lines.join('<br>');
    }
  }
  
  // Calculate new scroll position to keep the same canvas point under cursor
  const newScrollLeft = canvasX * canvasZoom - viewportX;
  const newScrollTop = canvasY * canvasZoom - viewportY;
  
  wrap.scrollLeft = newScrollLeft;
  wrap.scrollTop = newScrollTop;
  
  // Update pixel marker position after zoom
  if (selectedByteIdx >= 0) {
    updatePixelMarker(selectedByteIdx);
  }
}

canvas.addEventListener('wheel', (ev) => {
  if (ev.ctrlKey || ev.metaKey) {
    ev.preventDefault();
    
    const delta = -ev.deltaY;
    const zoomSpeed = 0.005 * zoomSensitivity;
    const newZoom = canvasZoom + delta * zoomSpeed;
    const clientX = ev.clientX;
    const clientY = ev.clientY;
    
    // Batch zoom updates via RAF to prevent jank
    if (pendingZoomUpdate) {
      cancelAnimationFrame(pendingZoomUpdate);
    }
    pendingZoomUpdate = requestAnimationFrame(() => {
      pendingZoomUpdate = null;
      updateCanvasZoom(newZoom, clientX, clientY);
    });
  }
}, { passive: false });

let lastGestureScale = 1;
let gestureCenterX = 0;
let gestureCenterY = 0;

canvas.addEventListener('gesturestart', (ev) => {
  ev.preventDefault();
  lastGestureScale = 1;
  gestureCenterX = ev.clientX;
  gestureCenterY = ev.clientY;
});

canvas.addEventListener('gesturechange', (ev) => {
  ev.preventDefault();
  
  let scaleDelta = ev.scale / lastGestureScale;
  // Apply sensitivity: interpolate between 1.0 (no change) and scaleDelta
  const sensitivity = zoomSensitivity;
  scaleDelta = 1.0 + (scaleDelta - 1.0) * sensitivity;
  
  const newZoom = canvasZoom * scaleDelta;
  lastGestureScale = ev.scale;
  
  updateCanvasZoom(newZoom, gestureCenterX, gestureCenterY);
});

canvas.addEventListener('gestureend', (ev) => {
  ev.preventDefault();
  lastGestureScale = 1;
});

// ──────────────────────────────────────────────────────────────────────
// localStorage persistence
// ──────────────────────────────────────────────────────────────────────
function saveFileToStorage() {
  if (!fileData || !fileData.rawBytes) return;
  
  const MAX_STORAGE_SIZE = CONSTANTS.MAX_STORAGE_SIZE;
  
  // Pre-calculate base64 size (base64 is ~1.37x original size)
  const estimatedBase64Size = Math.ceil(fileData.rawBytes.length * 1.37);
  
  // Skip if file too large (with overhead for JSON structure)
  if (estimatedBase64Size > MAX_STORAGE_SIZE * 0.9) {
    console.log(`File too large for localStorage (estimated ${(estimatedBase64Size / (1024 * 1024)).toFixed(1)}MB > 5MB limit)`);
    updateStorageInfo();
    return;
  }
  
  try {
    // Loop-based base64 encoding to avoid stack overflow
    const CHUNK_SIZE = CONSTANTS.BASE64_CHUNK_SIZE;
    let base64 = '';
    
    for (let i = 0; i < fileData.rawBytes.length; i += CHUNK_SIZE) {
      const chunk = fileData.rawBytes.slice(i, i + CHUNK_SIZE);
      let binaryString = '';
      for (let j = 0; j < chunk.length; j++) {
        binaryString += String.fromCharCode(chunk[j]);
      }
      base64 += btoa(binaryString);
    }
    
    const data = {
      name: fileData.name,
      base64: base64,
      canvasWidth: canvasWidth,
      colorMode: colorMode,
      canvasZoom: canvasZoom,
      selectedByteIdx: selectedByteIdx
    };
    const jsonStr = JSON.stringify(data);
    localStorage.setItem('fileViewerData', jsonStr);
    cachedStorageSize = new Blob([jsonStr]).size;
    updateStorageInfo();
  } catch (e) {
    cachedStorageSize = null;
    if (e.name === 'QuotaExceededError') {
      console.warn('Storage quota exceeded:', e);
      statusContent.innerHTML = `<div style="color:#ff6666;padding:8px;background:#2a0000;border:1px solid #ff0000;border-radius:4px;margin:8px 0;">⚠️ <strong>Storage Full</strong><br>Cannot save file to browser storage (quota exceeded).<br>Clear storage or use a smaller file.</div>`;
    } else {
      console.warn('Failed to save to localStorage:', e);
    }
    updateStorageInfo();
  }
}

function updateStorageInfo() {
  const storageInfoEl = document.getElementById('storageInfo');
  try {
    const stored = localStorage.getItem('fileViewerData');
    if (stored) {
      if (cachedStorageSize === null) {
        cachedStorageSize = new Blob([stored]).size;
      }
      const sizeMB = (cachedStorageSize / (1024 * 1024)).toFixed(2);
      storageInfoEl.textContent = `Storage: 1 file (${sizeMB} MB)`;
    } else {
      // Check if current file is loaded but not stored
      if (fileData && fileData.rawBytes) {
        const fileSizeMB = (fileData.rawBytes.length / (1024 * 1024)).toFixed(1);
        if (fileData.rawBytes.length > 5 * 1024 * 1024) {
          storageInfoEl.textContent = `Storage: file too large (${fileSizeMB}MB > 5MB)`;
        } else {
          storageInfoEl.textContent = 'Storage: empty';
        }
      } else {
        storageInfoEl.textContent = 'Storage: empty';
      }
    }
  } catch (e) {
    storageInfoEl.textContent = 'Storage: error';
  }
}

function clearFileStorage() {
  try {
    localStorage.removeItem('fileViewerData');
    cachedStorageSize = null;
    // Reset to initial state
    fileData = null;
    selectedByteIdx = -1;
    canvasZoom = 5.0;
    zoomLevelSlider.value = canvasZoom;
    zoomLevelValue.textContent = canvasZoom.toFixed(1);
    canvas.width = 1;
    canvas.height = 1;
    applyCanvasZoom(canvasZoom);
    ctx.fillStyle = '#000';
    ctx.fillRect(0, 0, 1, 1);
    fileName.textContent = '—';
    fileSize.textContent = '—';
    lineCount.textContent = '—';
    charCount.textContent = '—';
    renderTime.textContent = '—';
    statusContent.textContent = 'Drop file to page • Click on pixel to inspect';
    textPreview.style.display = 'none';
    pixelMarker.style.display = 'none';
    crosshairH.style.display = 'none';
    crosshairV.style.display = 'none';
    updateStorageInfo();
    return true;
  } catch (e) {
    console.warn('Failed to clear localStorage:', e);
    return false;
  }
}

function loadFileFromStorage() {
  try {
    const stored = localStorage.getItem('fileViewerData');
    if (!stored) return false;
    
    // Cancel any pending file loads
    currentFileLoadToken = null;
    
    const data = JSON.parse(stored);
    
    // Decode base64 back to bytes
    const binaryString = atob(data.base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    
    // Reconstruct fileData
    const decoder = new TextDecoder('utf-8', { fatal: false });
    const text = decoder.decode(bytes);
    const parsed = parseFile(text, bytes);
    
    fileData = {
      name: data.name,
      isBinary: true,
      rawBytes: bytes,
      ...parsed
    };
    
    // Restore UI state
    fileName.textContent = data.name;
    fileSize.textContent = formatBytes(bytes.length);
    lineCount.textContent = parsed.lines.length.toLocaleString();
    charCount.textContent = parsed.totalChars.toLocaleString();
    
    canvasWidth = data.canvasWidth || 1024;
    widthInput.value = canvasWidth;
    
    colorMode = data.colorMode || 'hsv';
    colorModeSelect.value = colorMode;
    
    canvasZoom = data.canvasZoom || 5.0;
    zoomLevelSlider.value = canvasZoom;
    zoomLevelValue.textContent = canvasZoom.toFixed(1);
    
    renderThumbnail(canvasWidth);
    
    if (data.selectedByteIdx >= 0) {
      selectedByteIdx = data.selectedByteIdx;
      displayBytePreview(selectedByteIdx);
    }
    
    updateStorageInfo();
    return true;
  } catch (e) {
    console.warn('Failed to load from localStorage:', e);
    return false;
  }
}

// Load saved file on page load
window.addEventListener('load', () => {
  // Initialize canvas to fill the viewport
  if (!fileData) {
    const canvasWrap = document.getElementById('canvasWrap');
    const wrapWidth = canvasWrap.clientWidth;
    const wrapHeight = canvasWrap.clientHeight;
    
    canvas.width = Math.max(wrapWidth, 100);
    canvas.height = Math.max(wrapHeight, 100);
    applyCanvasZoom(canvasZoom);
    ctx.fillStyle = '#000';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
  }
  
  // Check for demo parameter in URL
  const urlParams = new URLSearchParams(window.location.search);
  const demoFile = urlParams.get('demo');
  
  if (demoFile) {
    // Load demo file
    fetch(demoFile)
      .then(response => {
        if (!response.ok) throw new Error('Demo file not found');
        return response.blob();
      })
      .then(blob => {
        // Create File object and trigger the same processing as drop
        const file = new File([blob], demoFile, { type: blob.type || 'application/octet-stream' });
        
        // Simulate drop event processing
        const reader = new FileReader();
        reader.onload = (e) => {
          processFileData(file, e.target.result);
        };
        reader.onerror = (e) => {
          console.error('FileReader error:', e);
          statusContent.innerHTML = '<div style="color:#ff6666;padding:8px;">❌ Error reading demo file</div>';
          loadFileFromStorage();
        };
        reader.readAsArrayBuffer(file);
      })
      .catch(err => {
        console.warn('Failed to load demo file:', err);
        loadFileFromStorage();
      });
  } else {
    loadFileFromStorage();
  }
  
  updateStorageInfo();
});

// ──────────────────────────────────────────────────────────────────────
// Keyboard navigation: arrow keys to move selection by bytes
// ──────────────────────────────────────────────────────────────────────
document.addEventListener('keydown', (ev) => {
  if (!fileData || !fileData.rawBytes || selectedByteIdx < 0) return;
  
  if (ev.key === 'ArrowLeft') {
    ev.preventDefault();
    const newIdx = Math.max(0, selectedByteIdx - 1);
    displayBytePreview(newIdx);
  } else if (ev.key === 'ArrowRight') {
    ev.preventDefault();
    const newIdx = Math.min(fileData.rawBytes.length - 1, selectedByteIdx + 1);
    displayBytePreview(newIdx);
  } else if (ev.key === 'ArrowUp') {
    ev.preventDefault();
    const newIdx = Math.max(0, selectedByteIdx - canvasWidth);
    displayBytePreview(newIdx);
  } else if (ev.key === 'ArrowDown') {
    ev.preventDefault();
    const newIdx = Math.min(fileData.rawBytes.length - 1, selectedByteIdx + canvasWidth);
    displayBytePreview(newIdx);
  }
});

// Zoom control with +/= and - keys
document.addEventListener('keydown', (ev) => {
  if (ev.key === '+' || ev.key === '=') {
    ev.preventDefault();
    const zoomStep = calculateZoomStep(zoomSensitivity);
    const newZoom = canvasZoom + zoomStep;
    const wrap = document.getElementById('canvasWrap');
    const wrapRect = wrap.getBoundingClientRect();
    // Zoom toward center of visible scroll area
    const centerX = wrapRect.left + wrapRect.width / 2;
    const centerY = wrapRect.top + wrapRect.height / 2;
    updateCanvasZoom(newZoom, centerX, centerY);
    saveFileToStorage();
  } else if (ev.key === '-' || ev.key === '_') {
    ev.preventDefault();
    const zoomStep = calculateZoomStep(zoomSensitivity);
    const newZoom = canvasZoom - zoomStep;
    const wrap = document.getElementById('canvasWrap');
    const wrapRect = wrap.getBoundingClientRect();
    // Zoom toward center of visible scroll area
    const centerX = wrapRect.left + wrapRect.width / 2;
    const centerY = wrapRect.top + wrapRect.height / 2;
    updateCanvasZoom(newZoom, centerX, centerY);
    saveFileToStorage();
  }
});

// ──────────────────────────────────────────────────────────────────────
// Drag & Drop
// ──────────────────────────────────────────────────────────────────────
let dragCounter = 0;

document.addEventListener('dragenter', (ev) => {
  ev.preventDefault();
  ev.stopPropagation();
  dragCounter++;
  dropzone.classList.add('active');
});

document.addEventListener('dragleave', (ev) => {
  ev.preventDefault();
  ev.stopPropagation();
  dragCounter--;
  if (dragCounter === 0) {
    dropzone.classList.remove('active');
  }
});

document.addEventListener('dragover', (ev) => {
  ev.preventDefault();
  ev.stopPropagation();
});

document.addEventListener('drop', (ev) => {
  ev.preventDefault();
  ev.stopPropagation();
  dragCounter = 0;
  dropzone.classList.remove('active');
  
  const files = ev.dataTransfer.files;
  if (files.length === 0) return;
  
  const file = files[0];
  
  // Issue 25: File size validation
  if (file.size > CONSTANTS.MAX_FILE_SIZE) {
    const sizeMB = (file.size / (1024 * 1024)).toFixed(1);
    const maxMB = (CONSTANTS.MAX_FILE_SIZE / (1024 * 1024)).toFixed(0);
    alert(`File too large: ${sizeMB}MB\n\nMaximum supported size: ${maxMB}MB\n\nPlease select a smaller file.`);
    return;
  }
  
  // Issue 25: Warning for large files
  if (file.size > CONSTANTS.WARN_FILE_SIZE) {
    const sizeMB = (file.size / (1024 * 1024)).toFixed(1);
    if (!confirm(`This is a large file (${sizeMB}MB).\n\nProcessing may take several seconds and use significant memory.\n\nContinue?`)) {
      return;
    }
  }
  
  fileName.textContent = file.name;
  fileSize.textContent = formatBytes(file.size);
  
  // Issue 27: Show loading state
  statusContent.innerHTML = '<div style="color:#00aaff;padding:8px;">⏳ Loading file...</div>';
  textPreview.style.display = 'none';
  
  canvasZoom = 5.0;
  zoomLevelSlider.value = canvasZoom;
  zoomLevelValue.textContent = canvasZoom.toFixed(1);
  
  // Read as ArrayBuffer first to detect binary
  const reader = new FileReader();
  
  // Issue 26: Error boundary for file reading
  reader.onerror = (e) => {
    console.error('FileReader error:', e);
    statusContent.innerHTML = '<div style="color:#ff6666;padding:8px;background:#2a0000;border:1px solid #ff0000;border-radius:4px;">❌ <strong>Error reading file</strong><br>The file could not be read. It may be corrupted or inaccessible.</div>';
    fileName.textContent = '—';
    fileSize.textContent = '—';
  };
  
  reader.onload = (e) => {
    processFileData(file, e.target.result);
  };
  reader.readAsArrayBuffer(file);
});

// ──────────────────────────────────────────────────────────────────────
// Process file data (shared by drop and demo loading)
// ──────────────────────────────────────────────────────────────────────
function processFileData(file, arrayBuf) {
  try {
    // Issue 27: Update loading state
    statusContent.innerHTML = '<div style="color:#00aaff;padding:8px;">⏳ Processing file data...</div>';
    
    const bytes = new Uint8Array(arrayBuf);
      
      // Issue 27: Update loading state
      statusContent.innerHTML = '<div style="color:#00aaff;padding:8px;">⏳ Detecting file format...</div>';
      
      // Detect binary: check for null bytes or high ratio of non-printable chars
      let nonPrintable = 0;
      const sampleSize = Math.min(8192, bytes.length);
      for (let i = 0; i < sampleSize; i++) {
        const b = bytes[i];
        if (b === 0 || (b < 32 && b !== 9 && b !== 10 && b !== 13) || b > 126) {
          nonPrintable++;
        }
      }
      const isBinary = nonPrintable > sampleSize * 0.3;
      
      // Issue 27: Update loading state
      statusContent.innerHTML = '<div style="color:#00aaff;padding:8px;">⏳ Parsing file structure...</div>';
      
      // Convert to text for parsing
      const decoder = new TextDecoder('utf-8', { fatal: false });
      const text = decoder.decode(bytes);
      const parsed = parseFile(text, bytes);
      
      fileData = { 
        name: file.name, 
        isBinary: isBinary,
        rawBytes: bytes,
        ...parsed 
      };
      
      // ELF Detection
      const elfDetection = detectELFFormat(bytes);
      if (elfDetection && elfDetection.isELF) {
        console.log('ELF file detected:', elfDetection);
        try {
          const elfFile = new ELFModel.ELFFile(bytes.buffer);
          const loadResult = elfFile.load(false);
          if (loadResult === ELFModel.ELFFileLoadResult.OK) {
            appState.elfInfo = elfDetection;
            appState.elfStructure = elfFile;
            console.log('ELF parsed successfully:');
            console.log('  Class:', elfFile.elfHeader.E_ident_class.description());
            console.log('  Type:', elfFile.elfHeader.E_type.description());
            console.log('  Machine:', elfFile.elfHeader.E_machine.description());
            console.log('  Sections:', elfFile.getNumOfSectionHeaderTables());
            console.log('  Program Headers:', elfFile.getNumOfProgramHeaderTables());
            
            // Extract section boundaries
            appState.sectionOverlays = [];
            
            // ELF Header
            const headerSize = elfFile.elfHeader.E_Ehsize.Get32BitValue();
            appState.sectionOverlays.push({
              start: 0,
              end: headerSize,
              label: 'ELF Header',
              color: '#FFFF00'
            });
            
            // Program Headers
            const phOff = elfFile.elfHeader.E_PhOff.Get32BitValue();
            const phNum = elfFile.elfHeader.E_Phnum.Get32BitValue();
            const phEntSize = elfFile.elfHeader.E_Phentsize.Get32BitValue();
            if (phNum > 0 && phOff > 0) {
              appState.sectionOverlays.push({
                start: phOff,
                end: phOff + (phNum * phEntSize),
                label: `Program Headers (${phNum})`,
                color: '#00FFFF'
              });
            }
            
            // Section Headers
            const shOff = elfFile.elfHeader.E_ShOff.Get32BitValue();
            const shNum = elfFile.elfHeader.E_Shnum.Get32BitValue();
            const shEntSize = elfFile.elfHeader.E_Shentsize.Get32BitValue();
            if (shNum > 0 && shOff > 0) {
              appState.sectionOverlays.push({
                start: shOff,
                end: shOff + (shNum * shEntSize),
                label: `Section Headers (${shNum})`,
                color: '#FF00FF'
              });
            }
            
            // Individual Sections - assign brightest neon colors
            const sectionColors = [
              '#00FF00', '#00FFFF', '#FF00FF', '#FFFF00', '#FF0000',
              '#00FF88', '#FF00AA', '#AAFF00', '#00AAFF', '#FF88FF',
              '#88FF00', '#FF0088', '#00FF44', '#FF4400', '#44FF00'
            ];
            
            for (let i = 0; i < elfFile.getNumOfSectionHeaderTables(); i++) {
              const section = elfFile.elfSectionHeaderTables[i];
              const secOffset = section.Sh_Offset.Get32BitValue();
              const secSize = section.Sh_Size.Get32BitValue();
              const secName = section.getName();
              
              if (secSize > 0 && secOffset > 0) {
                appState.sectionOverlays.push({
                  start: secOffset,
                  end: secOffset + secSize,
                  label: secName || `Section ${i}`,
                  color: sectionColors[i % sectionColors.length]
                });
              }
            }
            
            console.log(`Extracted ${appState.sectionOverlays.length} ELF regions for overlay`);
            
            // Show highlight and blink checkboxes
            highlightSectionsLabel.style.display = 'block';
            blinkSectionsLabel.style.display = 'block';
            blinkSectionsLabel.style.display = 'block';
            
            // Render ELF info panel
            renderELFInfoPanel();
          }
        } catch (e) {
          console.error('ELF parsing failed:', e);
          appState.elfInfo = null;
          appState.elfStructure = null;
        }
      } else {
        appState.elfInfo = null;
        appState.elfStructure = null;
        appState.sectionOverlays = [];
        elfInfo.style.display = 'none';
        highlightSectionsLabel.style.display = 'none';
        blinkSectionsLabel.style.display = 'none';
      }
      
      lineCount.textContent = parsed.lines.length.toLocaleString();
      charCount.textContent = parsed.totalChars.toLocaleString();
      
      // Issue 27: Update loading state
      statusContent.innerHTML = '<div style="color:#00aaff;padding:8px;">⏳ Rendering visualization...</div>';
      
      // Calculate optimal canvas width based on file size
      canvasWidth = calculateOptimalWidth(bytes.length);
      widthInput.value = canvasWidth;
      
      // Suggest grayscale for very large files in HSV mode
      if (bytes.length > 50 * 1024 * 1024 && colorMode === 'hsv') {
        console.log(`Large file detected (${(bytes.length / (1024 * 1024)).toFixed(1)}MB). Consider switching to Grayscale mode for faster initial render.`);
      }
      
      renderThumbnail(canvasWidth);
      
      // Issue 27: Clear loading state
      statusContent.textContent = 'Click on pixel to inspect';
      
      // Auto-select initial byte position (10x10 or 0x0)
      const initialByteIdx = Math.min(10 * canvasWidth + 10, bytes.length - 1);
      if (initialByteIdx >= 0) {
        displayBytePreview(initialByteIdx);
      }
      
      // Save to localStorage for persistence
      saveFileToStorage();
    } catch (error) {
      // Issue 26: Error boundary for processing
      console.error('Error processing file:', error);
      statusContent.innerHTML = `<div style="color:#ff6666;padding:8px;background:#2a0000;border:1px solid #ff0000;border-radius:4px;margin:8px 0;">❌ <strong>Error processing file</strong><br>${escapeHtml(error.message)}<br><br>The file may be corrupted or in an unsupported format.</div>`;
      fileName.textContent = '—';
      fileSize.textContent = '—';
      lineCount.textContent = '—';
      charCount.textContent = '—';
    }
}

// ──────────────────────────────────────────────────────────────────────
// Manual controls
// ──────────────────────────────────────────────────────────────────────

// Hex view click handler - select corresponding pixel
statusContent.addEventListener('click', (ev) => {
  if (!fileData || !fileData.rawBytes) return;
  
  const target = ev.target;
  
  // Only handle clicks directly on hex byte spans with data-byte-offset attribute
  // Ignore clicks on whitespace, between bytes, on ASCII section, etc.
  if (target.tagName === 'SPAN' && target.hasAttribute('data-byte-offset')) {
    const byteOffset = parseInt(target.getAttribute('data-byte-offset'));
    if (byteOffset >= 0 && byteOffset < fileData.rawBytes.length) {
      displayBytePreview(byteOffset);
    }
  }
  // Remove fallback parsing - only accept direct clicks on hex byte spans
});

widthInput.addEventListener('change', () => {
  let newWidth = parseInt(widthInput.value, 10) || 1024;
  newWidth = Math.max(1, Math.min(64000, newWidth));
  canvasWidth = newWidth;
  widthInput.value = newWidth;
  renderThumbnail(canvasWidth);
  saveFileToStorage();
});

colorModeSelect.addEventListener('change', () => {
  colorMode = colorModeSelect.value;
  renderThumbnail(canvasWidth);
  saveFileToStorage();
});

zoomLevelSlider.addEventListener('input', () => {
  canvasZoom = parseFloat(zoomLevelSlider.value);
  zoomLevelValue.textContent = canvasZoom.toFixed(1);
  applyCanvasZoom(canvasZoom);
  if (selectedByteIdx >= 0) {
    updatePixelMarker(selectedByteIdx);
  }
  saveFileToStorage();
});

zoomSensSlider.addEventListener('input', () => {
  zoomSensitivity = parseFloat(zoomSensSlider.value);
  zoomSensValue.textContent = zoomSensitivity.toFixed(1);
});

hexViewCheckbox.addEventListener('change', () => {
  hexViewOverride = hexViewCheckbox.checked;
  // Refresh preview if there's a selected byte
  if (selectedByteIdx >= 0) {
    displayBytePreview(selectedByteIdx);
  }
});

showCrosshairCheckbox.addEventListener('change', () => {
  showCrosshair = showCrosshairCheckbox.checked;
  // Update crosshair visibility and refresh hex view
  if (selectedByteIdx >= 0) {
    displayBytePreview(selectedByteIdx);
  }
});

highlightSectionsCheckbox.addEventListener('change', () => {
  renderELFOverlays();
});

blinkSectionsCheckbox.addEventListener('change', () => {
  renderELFOverlays();
});

blinkSectionsCheckbox.addEventListener('change', () => {
  renderELFOverlays();
});

saveButton.addEventListener('click', () => {
  if (!fileData || !canvas.width || !canvas.height) {
    alert('No image to save. Please load a file first.');
    return;
  }
  
  // Generate timestamp: YYYY-MM-DD_HH-MM-SS.mmm
  const now = new Date();
  const yyyy = now.getFullYear();
  const mm = String(now.getMonth() + 1).padStart(2, '0');
  const dd = String(now.getDate()).padStart(2, '0');
  const hh = String(now.getHours()).padStart(2, '0');
  const min = String(now.getMinutes()).padStart(2, '0');
  const ss = String(now.getSeconds()).padStart(2, '0');
  const msec = String(now.getMilliseconds()).padStart(3, '0');
  
  // Get base filename without extension
  const baseName = fileData.name.replace(/\.[^.]*$/, '');
  const timestamp = `${yyyy}-${mm}-${dd}_${hh}-${min}-${ss}.${msec}`;
  const filename = `${timestamp}_${baseName}.png`;
  
  // Export canvas as PNG (lossless)
  canvas.toBlob((blob) => {
    if (!blob) {
      alert('Failed to generate image');
      return;
    }
    
    // Create download link
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, 'image/png');
});

const clearStorageBtn = document.getElementById('clearStorageBtn');
clearStorageBtn.addEventListener('click', () => {
  if (confirm('Clear stored file from browser? This cannot be undone.')) {
    clearFileStorage();
  }
});

// ──────────────────────────────────────────────────────────────────────
// Utility
// ──────────────────────────────────────────────────────────────────────
function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function formatHexdump(bytes, startOffset, centerOffset, contextLines, showCrosshair, clickedOffset) {
  // Format lines: contextLines before, center (with clicked byte), contextLines after
  // centerOffset: determines which lines to show (the window center)
  // clickedOffset: determines which byte to highlight (defaults to centerOffset if not provided)
  if (clickedOffset === undefined) {
    clickedOffset = centerOffset;
  }
  
  const bytesPerLine = 16;
  const centerLine = Math.floor(centerOffset / bytesPerLine);
  const clickedLine = Math.floor(clickedOffset / bytesPerLine);
  const clickedColumn = clickedOffset % bytesPerLine;
  const startLine = Math.max(0, centerLine - contextLines);
  const endLine = Math.min(Math.floor(bytes.length / bytesPerLine) + 1, centerLine + contextLines + 1);
  
  // Use template literals for better performance
  const lines = [];
  const textColor = '#00ffff';
  const backColor = '#ff0000';

  for (let lineNum = startLine; lineNum < endLine; lineNum++) {
    const lineOffset = lineNum * bytesPerLine;
    const lineBytes = [];
    const ascii = [];
    
    for (let i = 0; i < bytesPerLine; i++) {
      const idx = lineOffset + i;
      if (idx < bytes.length) {
        const byte = bytes[idx];
        const isClicked = idx === clickedOffset;
        // Use absolute byte offset for crosshair calculation, not relative line number
        const byteColumn = idx % bytesPerLine;
        const isClickedColumn = showCrosshair && (byteColumn === clickedColumn);
        const isClickedLine = showCrosshair && (lineNum === clickedLine);
        const hexStr = byte.toString(16).padStart(2, '0');
        
        // Apply backgrounds: grey for crosshair, cyan for clicked byte
        // Add data-byte-offset for click handling
        let hexStyle = '';
        if (isClicked) {
          lineBytes.push(`<span data-byte-offset="${idx}" style="background:${backColor};color:${textColor}!important;font-weight:bold;cursor:pointer">${hexStr}</span>`);
          hexStyle = 'done';
        } else if (isClickedLine || isClickedColumn) {
          hexStyle = `background:rgba(128,128,128,0.5);cursor:pointer`;
        }
        
        if (hexStyle && hexStyle !== 'done') {
          lineBytes.push(`<span data-byte-offset="${idx}" style="${hexStyle}">${hexStr}</span>`);
        } else if (!hexStyle) {
          lineBytes.push(`<span data-byte-offset="${idx}" style="cursor:pointer">${hexStr}</span>`);
        }
        
        // ASCII representation
        const ch = (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
        let asciiStyle = '';
        if (isClicked) {
          ascii.push(`<span data-byte-offset="${idx}" style="background:${backColor};color:${textColor}!important;font-weight:bold;cursor:pointer">${escapeHtml(ch)}</span>`);
          asciiStyle = 'done';
        } else if (isClickedLine || isClickedColumn) {
          asciiStyle = `background:rgba(128,128,128,0.5);cursor:pointer`;
        }
        
        if (asciiStyle && asciiStyle !== 'done') {
          ascii.push(`<span data-byte-offset="${idx}" style="${asciiStyle}">${escapeHtml(ch)}</span>`);
        } else if (!asciiStyle) {
          ascii.push(`<span data-byte-offset="${idx}" style="cursor:pointer">${escapeHtml(ch)}</span>`);
        }
      } else {
        lineBytes.push('  ');
        ascii.push(' ');
      }
    }
    
    // Format: offset  hex bytes (8) (8)  |ascii| using template literals
    const offset = lineOffset.toString(16).padStart(8, '0');
    const hexPart1 = lineBytes.slice(0, 8).join(' ');
    const hexPart2 = lineBytes.slice(8, 16).join(' ');
    const asciiStr = ascii.join('');
    
    lines.push(`${offset}  ${hexPart1}  ${hexPart2}  |${asciiStr}|`);
  }
  
  return lines.join('\n');
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}
