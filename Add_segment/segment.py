class AddSegment:
    def __init__(self,file_path,segment_name,virtul_size,Segment_value):
        self.object_file=open(file_path,"rb").read()
        self.segment_name=segment_name.encode()
        self.virtul_size=virtul_size
        self.Segment_value=Segment_value
        self.NT_Offset=bytes2int(self.object_file[0x3c:0x40])
        self.NumberOfSetions=bytes2int(self.object_file[self.NT_Offset+6:self.NT_Offset+8])
        self.SizeOfImage=bytes2int(self.object_file[self.NT_Offset+0x50:self.NT_Offset+0x54])
    
    def Make_New_Segment_Header(self):
        self.new_header=self.segment_name+(8-len(self.segment_name))*b"\x00"
        self.new_header+=self.virtul_size.to_bytes(4,"little")
        self.LastSegmentHead_VirtualAddress_add_SizeOfRawData=bytes2int(self.object_file[self.NT_Offset+0x108+40*(self.NumberOfSetions-1)+12:self.NT_Offset+0x108+40*(self.NumberOfSetions-1)+16])+bytes2int(self.object_file[self.NT_Offset+0x108+40*(self.NumberOfSetions-1)+16:self.NT_Offset+0x108+40*(self.NumberOfSetions-1)+20])
        if (self.LastSegmentHead_VirtualAddress_add_SizeOfRawData+self.virtul_size)%0x1000==0:
            self.new_header+=self.LastSegmentHead_VirtualAddress_add_SizeOfRawData.to_bytes(4,"little")
        else:
            self.new_header+=(self.LastSegmentHead_VirtualAddress_add_SizeOfRawData+0x1000-self.LastSegmentHead_VirtualAddress_add_SizeOfRawData%0x1000).to_bytes(4,"little")
        self.new_header+=self.virtul_size.to_bytes(4,"little")
        self.LastSegmentHead_PointerToRawData=bytes2int(self.object_file[self.NT_Offset+0x108+40*(self.NumberOfSetions-1)+20:self.NT_Offset+0x108+40*(self.NumberOfSetions-1)+24])
        self.new_header+=(self.LastSegmentHead_PointerToRawData+self.virtul_size).to_bytes(4,"little")
        self.new_header+=0x0.to_bytes(16,"little")
        self.new_header+=self.Segment_value
    
    def Make_New_Segment(self,write_date):
        self.New_Segment=self.object_file[:self.NT_Offset+0x108+40*self.NumberOfSetions]
        self.New_Segment+=self.new_header
        if len(self.New_Segment)%0x200!=0:
            self.New_Segment+=(0x200-len(self.New_Segment)%0x200)*b"\x00"
        if (self.NT_Offset+0x108+40*self.NumberOfSetions)%0x200!=0:
            self.Header_end=((self.NT_Offset+0x108+40*self.NumberOfSetions)//0x200+1)*0x200
        self.New_Segment+=self.object_file[self.Header_end:]
        self.New_Segment+=write_date
        self.New_Segment=self.New_Segment[:self.NT_Offset+6]+(self.NumberOfSetions+1).to_bytes(2,"little")+self.New_Segment[self.NT_Offset+8:self.NT_Offset+0x50]+(self.SizeOfImage+0x1000).to_bytes(4,"little")+self.New_Segment[self.NT_Offset+0x54:]

    def save(self,file_path):
        f=open(file_path,"wb")
        f.write(self.New_Segment)
        f.close()

bytes2int = lambda value:int.from_bytes(value,"little") 

if __name__ == "__main__":
    #A = Analyses_PE_Header("C:\\Users\\axe\\Documents\\C\\c.exe")
    #A.Sections_value()
    A=AddSegment("C:\\Users\\axe\\Documents\\C\\c.exe",".mysgm",0x200,b"\x20\x00\x00\x60")
    A.Make_New_Segment_Header()
    A.Make_New_Segment(b"\x00"*0x1000)
    A.save("c3.exe")

