class FILE_HEADER:
    def __init__(self,file_header):
        self.Machine=bytes2hex(file_header[:2])
        self.NumberOfSections=bytes2hex(file_header[2:4])
        self.TimeDateStamp=bytes2hex(file_header[4:8])
        self.PointerToSymbolTable=bytes2hex(file_header[8:12])
        self.NumberOfSymbols=bytes2hex(file_header[12:16])
        self.SizeOfOptionalHeader=bytes2hex(file_header[16:18])
        self.Characteristics=bytes2hex(file_header[18:])

class OPTIONAL_HEADER:
    def __init__(self,optional_header):
        self.Magic=bytes2hex(optional_header[:2])
        self.MajorLinkerVersion=optional_header[2]
        self.MinorLinkerVersion=optional_header[3]
        self.SizeOfCode=bytes2hex(optional_header[4:8])
        self.SizeOfInitializedData=bytes2hex(optional_header[8:12])
        self.SizeOfUninitializedData=bytes2hex(optional_header[12:16])
        self.AddressOfEntryPoint=bytes2hex(optional_header[16:20])
        self.BaseOfCode=bytes2hex(optional_header[20:24])
        self.BaseOfData=bytes2hex(optional_header[24:28])
        self.ImageBase=bytes2hex(optional_header[28:32])
        self.SectionAlignment=bytes2hex(optional_header[32:36])
        self.FileAlignment=bytes2hex(optional_header[36:40])
        self.MajorOperatingSystemVersion=bytes2hex(optional_header[40:42])
        self.MinorOperatingSystemVersion=bytes2hex(optional_header[42:44])
        self.MajorImageVersion=bytes2hex(optional_header[44:46])
        self.MinorImageVersion=bytes2hex(optional_header[46:48])
        self.MajorSubsystemVersion=bytes2hex(optional_header[48:50])
        self.MinorSubsystemVersion=bytes2hex(optional_header[50:52])
        self.Win32VersionValue=bytes2hex(optional_header[52:56])
        self.SizeOfImage=bytes2hex(optional_header[56:60])
        self.SizeOfHeaders=bytes2hex(optional_header[60:64])
        self.CheckSum=bytes2hex(optional_header[64:68])
        self.Subsystem=bytes2hex(optional_header[68:70])
        self.DllCharacteristics=bytes2hex(optional_header[70:72])
        self.SizeOfStackReserve=bytes2hex(optional_header[72:80])
        self.SizeOfStackCommit=bytes2hex(optional_header[80:88])
        self.SizeOfHeapReserve=bytes2hex(optional_header[88:96])
        self.SizeOfHeapCommit=bytes2hex(optional_header[96:104])
        self.LoaderFlags=bytes2hex(optional_header[104:108])
        self.NumberOfRvaAndSizes=bytes2hex(optional_header[108:112])
        self.DataDirectory=[optional_header[112+i*8:112+(i+1)*8] for i in range(16)]

class SECTION_HEADER:
    def __init__(self,section_header):
        self.Name=section_header[:8]
        self.UnionMisc=bytes2hex(section_header[8:12])
        self.VirtualAddress=bytes2hex(section_header[12:16])
        self.SizeOfRawData=bytes2hex(section_header[16:20])
        self.PointerToRawData=bytes2hex(section_header[20:24])
        self.PointerToRelocations=bytes2hex(section_header[24:28])
        self.PointerToLinenumbers=bytes2hex(section_header[28:32])
        self.NumberOfRelocations=bytes2hex(section_header[32:34])
        self.NumberOfLinenumbers=bytes2hex(section_header[34:36])
        self.Characteristics=bytes2hex(section_header[36:40])

class Analyses_PE:
    def __init__(self,File_path):
        self.object_hex=open(File_path,"rb").read()
        self.NT_Offset=int(bytes2hex(self.object_hex[0x3c:0x40]),16)
        self.File_Header=FILE_HEADER(self.object_hex[self.NT_Offset+4:self.NT_Offset+24])
        self.Option_Header=OPTIONAL_HEADER(self.object_hex[self.NT_Offset+24:self.NT_Offset+24+15*16])
        if self.NT_Offset+24+15*16+eval(self.File_Header.NumberOfSections)*40 % 0x200==0:
            self.Header_End=self.NT_Offset+24+15*16+eval(self.File_Header.NumberOfSections)*40
        self.Header_End=self.NT_Offset+24+15*16+eval(self.File_Header.NumberOfSections)*40-(self.NT_Offset+24+15*16+eval(self.File_Header.NumberOfSections)*40)%0x200+0x200
        print(self.Header_End)

    def Sections_value(self):
        for segementname in range(eval(self.File_Header.NumberOfSections)):
            segement=SECTION_HEADER(self.object_hex[self.NT_Offset+24+15*16+segementname*40:self.NT_Offset+24+15*16+(segementname+1)*40])
            for i in segement.__dict__:
                print(f"\t{i} : {segement.__dict__[i]}")
            print()

    def Show_NT_Header_value(self):
        for i in self.File_Header.__dict__:
            print(f"\t{i} : {self.File_Header.__dict__[i]}")
        for i in self.Option_Header.__dict__:
            print(f"\t{i} : {self.Option_Header.__dict__[i]}") 
    

 
bytes2hex = lambda x:hex(int.from_bytes(x,"little"))
a=Analyses_PE("c.exe")
#a.Show_NT_Header_value()
#a.Sections_value()