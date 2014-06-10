module COFF

export readmeta

using StrPack

import Base: show

export readmeta, readheader, Sections, Symbols, debugsections, Relocations

include("constants.jl")

########## COFF.jl - An implementation of the PE/COFF File format ###############

#
# Represents the actual PE/COFF file
#
type COFFHandle{T<:IO}
    # The IO object. This field is speciallized on to avoid dispatch performance
    # hits, especially when operating on an IOBuffer, which is an important
    # usecase for in-memory files
    io::T
    # position(io) of the start of the file in the io stream.
    start::Int
    # position(io) of the COFF header. header == start iff the file is a COFF object
    # file (as opposed to a PE image file)
    header::Int
    # A uniqued strtab will be filled in on demand
    strtab
    COFFHandle(io,start,header) = new(io,start,header)
end
COFFHandle{T<:IO}(io::T,start,header) = COFFHandle{T}(io,start,header)

import Base: read, readuntil, readbytes, write, seek, seekstart, position

for f in (:read,:readuntil,:readbytes,:write)
    @eval $(f){T<:IO}(io::COFFHandle{T},args...) = $(f)(io.io,args...)
end


seek{T<:IO}(io::COFFHandle{T},pos) = seek(io.io,io.start+pos)
seekstart(io::COFFHandle) = seek(io.io,io.start)
position{T<:IO}(io::COFFHandle{T}) = position(io.io)-io.start

import StrPack: pack, unpack

unpack{T,ioT<:IO}(h::COFFHandle{ioT},::Type{T}) = unpack(h.io,T,:NativeEndian)
pack{T,ioT<:IO}(h::COFFHandle{ioT},::Type{T}) = pack(h.io,T,:NativeEndian)


#
# COFF Header
#
@struct immutable COFFHeader
    Machine::Uint16
    NumberOfSections::Uint16
    TimeDateStamp::Uint32
    PointerToSymbolTable::Uint32
    NumberOfSymbols::Uint32
    SizeOfOptionalHeader::Uint16
    Characteristics::Uint16
end

function printfield(io::IO,string,fieldlength)
    print(io," "^max(fieldlength-length(string),0))
    print(io,string)
end
printentry(io::IO,header,values...) = (printfield(io,header,21);println(io," ",values...))


using Dates

function show(io::IO,h::COFFHeader)
    printentry(io,"Machine",IMAGE_FILE_MACHINE[h.Machine])
    printentry(io,"NumberOfSections", h.NumberOfSections)
    printentry(io,"TimeDateStamp", Dates.DateTime(1970,1,1,0,0,0,0) + Dates.Second(h.TimeDateStamp))
    printentry(io,"PointerToSymbolTable", "0x",hex(h.PointerToSymbolTable))
    printentry(io,"NumberOfSymbols", h.NumberOfSymbols)
    printentry(io,"SizeOfOptionalHeader", h.SizeOfOptionalHeader)
    Characteristics = ASCIIString[]
    for (k,v) in IMAGE_FILE_CHARACTERISTICS
        ((k&h.Characteristics) != 0) && push!(Characteristics, v)
    end
    printentry(io,"Characteristics",join(Characteristics,", "))
end

#
# Optional Header
#
@struct immutable OptionalHeaderStandard
    Magic::Uint16
    MajorLinkerVersion::Uint8
    MinorLinkerVersion::Uint8
    SizeOfCode::Uint32
    SizeOfInitializedData::Uint32
    SizeOfUninitializedData::Uint32
    AddressOfEntryPoint::Uint32
    BaseOfCode::Uint32
end

@struct immutable IMAGE_DATA_DIRECTORY
    VirtualAddress::Uint32
    Size::Uint32
end

@struct immutable DataDirectories
    ExportTable::IMAGE_DATA_DIRECTORY
    ImportTable::IMAGE_DATA_DIRECTORY
    ResourceTable::IMAGE_DATA_DIRECTORY
    ExceptionTable::IMAGE_DATA_DIRECTORY
    CertificateTable::IMAGE_DATA_DIRECTORY
    BaseRelocatioNTable::IMAGE_DATA_DIRECTORY
    Debug::IMAGE_DATA_DIRECTORY
    Architecture::IMAGE_DATA_DIRECTORY
    GlobalPtr::IMAGE_DATA_DIRECTORY
    TLSTable::IMAGE_DATA_DIRECTORY
    LoadConfigTable::IMAGE_DATA_DIRECTORY
    BoundImport::IMAGE_DATA_DIRECTORY
    IAT::IMAGE_DATA_DIRECTORY
    DelayImportDescriptor::IMAGE_DATA_DIRECTORY
    CLRRuntimeHeader::IMAGE_DATA_DIRECTORY
    Reserverd::IMAGE_DATA_DIRECTORY
end

module PE32
    using StrPack
    import ..OptionalHeaderStandard, ..DataDirectories

    @struct immutable OptionalHeaderWindows
        ImageBase::Uint32
        SectionAlignment::Uint32
        FileAlignment::Uint32
        MajorOperatingSystemVersion::Uint16
        MinorOperatingSystemVersion::Uint16
        MajorImageVersion::Uint16
        MinorImageVersion::Uint16
        MajorSubsystemVersion::Uint16
        MinorSubsystemVersion::Uint16
        Win32VersionValue::Uint32
        SizeOfImage::Uint32
        SizeOfHeaders::Uint32
        CheckSum::Uint32
        Subsystem::Uint16
        DllCharacteristics::Uint16
        SizeOfStackReserve::Uint32
        SizeOfStackCommit::Uint32
        SizeOfHeapReserve::Uint32
        SizeOfHeapCommit::Uint32
        LoaderFlag::Uint32
        NumberOfRvaAndSizes::Uint32
    end


    @struct immutable OptionalHeader
        standard::OptionalHeaderStandard
        BaseOfData::Uint32
        windows::OptionalHeaderWindows
        directories::DataDirectories
    end

end


module PE32Plus
    using StrPack
    import ..OptionalHeaderStandard, ..DataDirectories

    @struct immutable OptionalHeaderWindows
        ImageBase::Uint64
        SectionAlignment::Uint32
        FileAlignment::Uint32
        MajorOperatingSystemVersion::Uint16
        MinorOperatingSystemVersion::Uint16
        MajorImageVersion::Uint16
        MinorImageVersion::Uint16
        MajorSubsystemVersion::Uint16
        MinorSubsystemVersion::Uint16
        Win32VersionValue::Uint32
        SizeOfImage::Uint32
        SizeOfHeaders::Uint32
        CheckSum::Uint32
        Subsystem::Uint16
        DllCharacteristics::Uint16
        SizeOfStackReserve::Uint64
        SizeOfStackCommit::Uint64
        SizeOfHeapReserve::Uint64
        SizeOfHeapCommit::Uint64
        LoaderFlag::Uint32
        NumberOfRvaAndSizes::Uint32
    end

    @struct immutable OptionalHeader
        standard::OptionalHeaderStandard
        windows::OptionalHeaderWindows
        directories::DataDirectories
    end
end

# Section Table

@struct immutable tiny_fixed_string
    str::Uint64
end

import Base: bytestring, show, print

function bytestring(x::tiny_fixed_string)
    a8 = reinterpret(Uint8,[x.str])
    z = findfirst(a8,0)
    UTF8String(a8[1:(z == 0 ? length(a8) : z-1)])
end
show(io::IO,x::tiny_fixed_string) = show(io,bytestring(x))
print(io::IO,x::tiny_fixed_string) = print(io,bytestring(x))

==(x::tiny_fixed_string,y::String) = bytestring(x) == y
==(x::String,y::tiny_fixed_string) = y==x

*(a::ASCIIString,b::tiny_fixed_string) = a*bytestring(b)

@struct immutable SectionHeader
    Name::tiny_fixed_string
    VirtualSize::Uint32
    VirtualAddress::Uint32
    SizeOfRawData::Uint32
    PointerToRawData::Uint32
    PointerToRelocations::Uint32
    PointerToLinenumbers::Uint32
    NumberOfRelocations::Uint16
    NumberOfLinenumbers::Uint16
    Characteristics::Uint32
end

function sectname(header::SectionHeader; strtab = nothing, errstrtab=true)
    name = bytestring(header.Name)
    if name[1] == '/'
        if strtab != nothing
            return strtab_lookup(strtab,parseint(name[2:end]))
        elseif errstrtab
            error("Section name refers to the strtab, but no strtab given")
        end
    end
    return name
end


function show(io::IO, header::SectionHeader; strtab = nothing)
    name = bytestring(header.Name)
    name2 = sectname(header; strtab = strtab, errstrtab=false)
    printentry(io,"Name",name,name!=name2?" => "*name2:"")
    printentry(io,"VirtualSize", "0x", hex(header.VirtualSize))
    printentry(io,"VirtualAddress", "0x", hex(header.VirtualAddress))
    printentry(io,"SizeOfRawData", "0x", hex(header.SizeOfRawData))
    printentry(io,"PointerToRawData", "0x", hex(header.PointerToRawData))
    printentry(io,"PointerToRelocations", "0x", hex(header.PointerToRelocations))
    printentry(io,"PointerToLinenumbers", "0x", hex(header.PointerToLinenumbers))
    printentry(io,"NumberOfRelocations", "0x", hex(header.NumberOfRelocations))
    printentry(io,"NumberOfLinenumbers", "0x", hex(header.NumberOfLinenumbers))
    Characteristics = ASCIIString[]
    for (k,v) in IMAGE_SCN_CHARACTERISTICS
        if k & IMAGE_SCN_ALIGN_MASK != 0
            continue
        end
        ((k&header.Characteristics) != 0) && push!(Characteristics, v)
    end
    if header.Characteristics & IMAGE_SCN_ALIGN_MASK != 0
        push!(Characteristics,
            IMAGE_SCN_CHARACTERISTICS[header.Characteristics & IMAGE_SCN_ALIGN_MASK])
    end
    printentry(io,"Characteristics",join(Characteristics,", "))
end

@struct immutable SymbolName
    name::Uint64
end

function show(io::IO, sname::SymbolName; strtab = nothing, showredirect=true)
    if sname.name & typemax(Uint32) == 0
        if strtab !== nothing
            if showredirect
                print(io, sname.name >> 32, " => ")
            end
            print(io,strtab_lookup(strtab,sname.name>>32))
        else
            print(io, "/", sname.name >> 32)
        end
    else
        print(io,bytestring(tiny_fixed_string(sname.name)))
    end
end

function symname(sname::SymbolName;  kwargs...)
    buf = IOBuffer()
    show(buf,sname; kwargs...)
    takebuf_string(buf)
end

@struct immutable SymtabEntry
    Name::SymbolName
    Value::Uint32
    SectionNumber::Uint16
    Type::Uint16
    StorageClass::Uint8
    NumberOfAuxSymbols::Uint8
end align_packed

symname(sname::SymtabEntry; kwargs...) = symname(sname.Name; kwargs...)

function show(io::IO, entry::SymtabEntry; strtab = nothing)
    print(io, "0x", hex(entry.Value, 8), " ")
    if entry.SectionNumber == 0
        printfield(io, "*UND*", 5)
    elseif entry.SectionNumber == uint16(-1)
        printfield(io, "*ABS*", 5)
    elseif entry.SectionNumber == uint16(-2)
        printfield(io, "*DBG*", 5)
    else
        printfield(io, dec(entry.SectionNumber), 5)
    end
    print(io, " ",hex(entry.Type, 4)," ")
    #print(io, IMAGE_SYM_CLASS[entry.StorageClass]," ")
    show(io, entry.Name; strtab = strtab)
end

@struct immutable RelocationEntry
    VirtualAddress::Uint32
    SymbolTableIndex::Uint32
    Type::Uint16
end align_packed

function show(io::IO, entry::RelocationEntry; machine=IMAGE_FILE_MACHINE_UNKNOWN, syms = northing, strtab=nothing)
    print(io, "0x", hex(entry.VirtualAddress,8), " ")
    if machine == IMAGE_FILE_MACHINE_UNKNOWN
        print(io,hex(entry.Type,4)," ")
    else
        printfield(io,MachineRelocationMap[machine][entry.Type],maximum(map(length,MachineRelocationMap[machine])))
    end
    printfield(io,"@"*string(dec(entry.SymbolTableIndex)),6)
    if syms !== nothing
        print(io," -> ",symname(syms[entry.SymbolTableIndex+1]; strtab = strtab))
    end
end

# # # Higer level interface

import Base: length, getindex, start, done, next

# # Sections
immutable Sections
    h::COFFHandle
    num::Uint16
    offset::Int
    Sections(h::COFFHandle, num::Uint16, offset::Int) = new(h,num,offset)
    function Sections(handle::COFFHandle,header::COFFHeader=readheader(handle))
        Sections(handle, header.NumberOfSections, handle.header + sizeof(COFFHeader) + header.SizeOfOptionalHeader)
    end
end

immutable SectionRef
    handle::COFFHandle
    no::Int
    offset::Int
    header::SectionHeader
end

sectname(ref::SectionRef) = sectname(ref.header; strtab=strtab(ref.handle))

function show(io::IO,x::SectionRef)
println(io,"0x",hex(x.offset,8),": Section #",x.no)
show(io, x.header; strtab=strtab(x.handle))
end

length(s::Sections) = s.num
const SectionHeaderSize = StrPack.calcsize(SectionHeader)
function getindex(s::Sections,n)
    if n < 1 || n > length(s)
        throw(BoundsError())
    end
    offset = s.offset + (n-1)*SectionHeaderSize
    seek(s.h,offset)
    SectionRef(s.h,n,offset,unpack(s.h, SectionHeader))
end

start(s::Sections) = 1
done(s::Sections,n) = n > length(s)
next(s::Sections,n) = (s[n],n+1)

# # Symbols
immutable Symbols
    h::COFFHandle
    num::Uint16
    offset::Int
    Symbols(h::COFFHandle, num, offset) = new(h,num,offset)
    function Symbols(handle::COFFHandle,header::COFFHeader=readheader(handle))
        Symbols(handle, header.NumberOfSymbols, header.PointerToSymbolTable)
    end
end

immutable SymbolRef
    handle::COFFHandle
    num::Uint16
    offset::Int
    entry::SymtabEntry
end
symname(sym::SymbolRef; kwargs...) = symname(sym.entry; kwargs...)

function show(io::IO,x::SymbolRef)
    print(io,'[')
    printfield(io,dec(x.num),5)
    print(io,"] ")
    show(io,x.entry; strtab=strtab(x.handle))
end

endof(s::Symbols) = s.num
const SymtabEntrySize = StrPack.calcsize(SymtabEntry)
function getindex(s::Symbols,n)
    if n < 1 || n > endof(s)
        throw(BoundsError())
    end
    offset = s.offset + (n-1)*SymtabEntrySize
    seek(s.h,offset)
    SymbolRef(s.h,n,offset,unpack(s.h, SymtabEntry))
end

start(s::Symbols) = 1
done(s::Symbols,n) = n > endof(s)
next(s::Symbols,n) = (x=s[n];(x,n+x.entry.NumberOfAuxSymbols+1))


# String table

immutable StrTab
    h::COFFHandle
    size::Int
    offset::Int
end

function StrTab(h::COFFHandle, header=readheader(h))
    offset = header.PointerToSymbolTable+header.NumberOfSymbols*SymtabEntrySize
    seek(h, offset)
    return StrTab(h,read(h,Uint32),offset)
end

function strtab(h::COFFHandle)
    if isdefined(h, :strtab)
        return h.strtab
    end
    h.strtab = StrTab(h)
end

function strtab_lookup(strtab::StrTab, offset)
    seek(strtab.h,offset+strtab.offset)
    # Strip trailing \0
    readuntil(strtab.h,'\0')[1:end-1]
end
#

const PEMAGIC = reinterpret(Uint32,Uint8['P','E','\0','\0'])[1]
const MZ = reinterpret(Uint16,Uint8['M','Z'])[1]
function readmeta(io::IO)
    start = position(io)
    if read(io,Uint16) == MZ
        # Get the PE Header offset
        seek(io, start+0x3c)
        off = read(io, Uint32)
        # PE File
        seek(io, start+off)
        read(io, Uint32) == PEMAGIC || error("Invalid PE magic")
    else
        seek(io,start)
    end
    COFFHandle(io,start,position(io))
end

readheader(h::COFFHandle) = (seek(h.io,h.header); unpack(h, COFFHeader))

### Relocation support

immutable Relocations
    h::COFFHandle
    machine::Int
    sect::SectionHeader
end

immutable RelocationRef
    h::COFFHandle
    machine::Int
    reloc::RelocationEntry
end

show(io::IO, x::RelocationRef) = show(io,x.reloc; machine=x.machine, syms=Symbols(x.h), strtab=strtab(x.h))

Relocations(s::SectionRef) = Relocations(s.handle,readheader(s.handle).Machine,s.header)

length(s::Relocations) = s.sect.NumberOfRelocations
const RelocationEntrySize = StrPack.calcsize(RelocationEntry)
function getindex(s::Relocations,n)
    if n < 1 || n > length(s)
        throw(BoundsError())
    end
    offset = s.sect.PointerToRelocations + (n-1)*RelocationEntrySize
    seek(s.h,offset)
    RelocationRef(s.h,s.machine,unpack(s.h, RelocationEntry))
end

start(s::Relocations) = 1
done(s::Relocations,n) = n > length(s)
next(s::Relocations,n) = (x=s[n];(x,n+1))

printtargetsymbol(io::IO,reloc::RelocationEntry, syms, strtab) = print(io,symname(syms[reloc.SymbolTableIndex+1]; strtab = strtab, showredirect = false))

function printRelocationInterpretation(io::IO, reloc::RelocationEntry, LocalValue::Uint64, machine, syms, sects, strtab)
    if machine == IMAGE_FILE_MACHINE_AMD64
        if reloc.Type == IMAGE_REL_AMD64_ABSOLUTE
            print(io,"0x",hex(LocalValue))
        elseif reloc.Type == IMAGE_REL_AMD64_ADDR64
            print(io,"(uint64_t) ")
            printtargetsymbol(io, reloc, syms, strtab)
            print(io," + 0x",hex(LocalValue,16))
        elseif reloc.Type == IMAGE_REL_AMD64_ADDR32
            print(io,"(uint32_t) ")
            printtargetsymbol(io, reloc, syms, strtab)
            print(io," + 0x",hex(LocalValue,8))
        elseif reloc.Type == IMAGE_REL_AMD64_ADDR32NB
            print(io,"(uint32_t) ")
            printtargetsymbol(io, reloc, syms, strtab)
            print(io," + 0x",hex(LocalValue,8))
            print(io," - ImageBase")
        elseif reloc.Type >= IMAGE_REL_AMD64_REL32 && reloc.Type <= IMAGE_REL_AMD64_REL32_5
            print(io,"(uint32_t) @pc-")
            printtargetsymbol(io, reloc, syms, strtab)
            print(io," + 0x",hex(LocalValue,8))
            add = reloc.Type-IMAGE_REL_AMD64_REL32
            print(io," + ",add)
        elseif reloc.Type == IMAGE_REL_AMD64_SECTION
            print(io,"(uint16_t) indexof(")
            printtargetsymbol(io, reloc, syms, strtab)
            print(io,")")
            LocalValue != 0 && print(io,"+",dec(LocalValue))
        elseif reloc.Type == IMAGE_REL_AMD64_SECREL
            print(io,"(uint32_t) ")
            printtargetsymbol(io, reloc, syms, strtab)
            print(io," - ")
            # Get the symbol's section
            sect = sects[syms[reloc.SymbolTableIndex].entry.SectionNumber]
            print(io,sectname(sect))
        else
            error("Unsupported Relocations")
        end
    else
        error("Relocation Support not implemented for this Machine Type")
    end
end

function relocationLength(reloc::RelocationEntry)
    reloc.Type == IMAGE_REL_AMD64_ABSOLUTE ? 0 :
    reloc.Type == IMAGE_REL_AMD64_ADDR64 ? 8 :
    reloc.Type >= IMAGE_REL_AMD64_ADDR32 &&
    reloc.Type <= IMAGE_REL_AMD64_REL32_5 ? 4 :
    reloc.Type == IMAGE_REL_AMD64_SECTION ? 2 :
    reloc.Type == IMAGE_REL_AMD64_SECREL ? 4 :
    reloc.Type == IMAGE_REL_AMD64_SECREL7 ? 1 :
    error("Unknown relocation type")
end

function inspectRelocations(sect::SectionRef, relocs = Relocations(sect))
    data = readbytes(sect);
    handle = sect.handle
    header = readheader(handle)
    for x in relocs[1:10]
      offset = x.reloc.VirtualAddress -sect.header.VirtualAddress
      size = COFF.relocationLength(x.reloc)
      # zext
      Local = reinterpret(Uint64,vcat(data[offset:offset+size],zeros(sizeof(Uint64)-size)))[1]
      print("*(",sectname(sect),"+0x",hex(offset,8),") = ")
      COFF.printRelocationInterpretation(STDOUT, x.reloc, Local, header.Machine, Symbols(handle), Sections(handle), COFF.strtab(handle))
      println()
    end
end

import Base: readbytes

readbytes{T<:IO}(io::COFFHandle{T},sec::SectionHeader) = (seek(io,sec.PointerToRawData); readbytes(io, sec.SizeOfRawData))
readbytes(sec::SectionRef) = readbytes(sec.handle,sec.header)

### DWARF support

using DWARF

function debugsections{T<:IO}(h::COFFHandle{T})
    sects = collect(Sections(h))
    snames = map(sectname,sects)
    sections = Dict{ASCIIString,SectionRef}()
    for i in 1:length(snames)
        # remove leading "."
        ind = findfirst(DWARF.DEBUG_SECTIONS,bytestring(snames[i])[2:end])
        if ind != 0
            sections[DWARF.DEBUG_SECTIONS[ind]] = sects[i]
        end
    end
    sections
end

end # module
