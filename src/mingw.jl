# Support for examining mingw-style pseudo relocations 

@struct immutable runtime_pseudo_reloc_item_v1
  addend::UInt32
  target::UInt32
end

@struct immutable runtime_pseudo_reloc_item_v2
  sym::UInt32
  target::UInt32
  flags::UInt32
end

@struct immutable runtime_pseudo_reloc_v2
  magic1::UInt32
  magic2::UInt32
  version::UInt32
end

let findsymbol(h, name) =
    first(filter(x->ObjFileBase.symname(x)==name, COFF.Symbols(h)))
  
  global dump_pseudo_relocs
  function dump_pseudo_relocs(h)
    start = findsymbol(h, "__RUNTIME_PSEUDO_RELOC_LIST__")
    last = findsymbol(h, "__RUNTIME_PSEUDO_RELOC_LIST_END__")
    seekstart(start)
    startpos = position(h)
    magic_struct = unpack(h, runtime_pseudo_reloc_v2)
    @assert (magic_struct.magic1 == 0 && magic_struct.magic2 == 0 &&
      magic_struct.version == 1) || error("Unsupported pseudo relocation format")
    while position(h) < startpos + (last.entry.Value - start.entry.Value)
      item = unpack(h, runtime_pseudo_reloc_item_v2)
      @show item
    end
  end
  
end
