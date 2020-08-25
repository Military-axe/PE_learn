# Add a segment in PE64

Intro:learn PE file format and Add a segment


<!-- more -->


先得稍微熟悉一下PE的文件格式
在文件中，对齐的尺度是0x200，在内存中对齐的尺度是0x1000


![](https://cdn.nlark.com/yuque/0/2020/png/2212593/1598319953140-79cef957-5f3c-4c10-a79b-ea76b0e713cc.png#align=left&display=inline&height=378&margin=%5Bobject%20Object%5D&originHeight=378&originWidth=524&size=0&status=done&style=none&width=524)


增加区段主要是对文件头修改和增加一个段


修改思路是


> 修改PE文件头中的NumberOfSections的值
> 修改PE拓展头重的SizeOfImage的值
> 增加一个区段描述表
> 增加一个区段



上面几点都很容易做到，两个头中值可以更具偏移改，看[010editor手写PE文件](https://www.cnblogs.com/by-clark/p/9129135.html)这篇可以知道这些属性具体在那个位置


需要注意的值，有些地方增加区段之后，要更具文件对齐的单位对齐


我随便找了一个程序，Stub_X64或010editor打开


![image.png](https://cdn.nlark.com/yuque/0/2020/png/2212593/1598320736569-4323ffae-a18f-499d-b709-e90b81019101.png#align=left&display=inline&height=504&margin=%5Bobject%20Object%5D&name=image.png&originHeight=1008&originWidth=1204&size=124003&status=done&style=none&width=602)


我的目标是在最后一个地方增加一个段叫`.myseg`大小是0x200,内容全0


NumberOfSection是区段数量，有几个区段就用那写几个


SizeOfImage映像大小，要把文件加载进内存需要的总大小，内存对齐后的--文件PE结构总长小于1000h，但是内存中的对齐粒度是1000h，所以PE结构被映射后要占1000h，尽管很多空间没有使用，另外，由于我增加的大小是0x200，增加一个区段头之后，并没有让PE结构超出0x1000，所以只需要sizeofimage增加0x1000就好


NumberOfSections和SizeOfImage很好改，用010很好找到对应位置


![image.png](https://cdn.nlark.com/yuque/0/2020/png/2212593/1598321175101-674e1c4e-e530-4995-a9a8-5f88c654209f.png#align=left&display=inline&height=935&margin=%5Bobject%20Object%5D&name=image.png&originHeight=1871&originWidth=1547&size=384350&status=done&style=none&width=773.5)


稍微麻烦的一点的来了，就是增加一个区段表，先看看区段表的一些信息


```cpp
typedef struct _IMAGE_SECTION_HEADER { 
BYTE Name[IMAGE_SIZEOF_SHORT_NAME];     1，区段的名字，只是一些约定俗称的名称
union { 
DWORD PhysicalAddress;                
DWORD VirtualSize; 
} Misc;                                  2，这个区段的大小，pe程序对此值的效验并没有那么严谨，但是最好与SizeOfRawData的值一致
DWORD VirtualAddress;                    3，区段的起始相对虚拟地址RVA，，比如我们.text是第一个区段，之前的所有文件大小对齐后占用的空间为1000h,那么这个值便是1000h，第二个区段的这个值是2000h
DWORD SizeOfRawData;                     4，区段在文件中的大小，是对齐后的，我们的代码较少，则这个值便是200h
DWORD PointerToRawData;                  5，区段的文件偏移，，，我们上面计算的PE文件头的大小刚好是200h，那么这个值便是200h，，后面的每个区段的这个值是，当前区段的SizeOfRawData+前一个区段的PointerToRawData
DWORD PointerToRelocations;              6，区段的重定位的信息的文件偏移，早OBJ文件中可用
DWORD PointerToLinenumbers;              7，没用
WORD NumberOfRelocations;                8，没用
WORD NumberOfLinenumbers;                9，没用
DWORD Characteristics;                  10，重要，这个区段的属性,(如代码/数据/可读/可写)的标志
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```
RVA就是OEP，现在不管，下篇文章我再改这个值，PointerToRawData这个值，要先去看最后一个区段的SizeOfRawData，用这个值再加上我们要增加的0x200,就是了


VirtualAddress的值要先去看最后一个区段，用最后一个区段的VirtualAddress+SizeOfRawData再对其0x200的尺度就可以了


最后直接文件尾部加入0x200个0就可以


稍微写了一个辅助的python脚本（就是学习中产生的垃圾，懒得改


```python
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
bytes2hex = lambda x:hex(int.from_bytes(x,"little"))

if __name__ == "__main__":
    #A = Analyses_PE_Header("C:\\Users\\axe\\Documents\\C\\c.exe")
    #A.Sections_value()
    A=AddSegment("C:\\Users\\axe\\Documents\\C\\c.exe",".mysgm",0x200,b"\x20\x00\x00\x60")
    A.Make_New_Segment_Header()
    A.Make_New_Segment(b"\x00"*0x1000)
    A.save("c3.exe")
```
看看C3.exe


![image.png](https://cdn.nlark.com/yuque/0/2020/png/2212593/1598322275094-4528279b-3409-4e05-9aaf-2b15eed2b6d8.png#align=left&display=inline&height=339&margin=%5Bobject%20Object%5D&name=image.png&originHeight=678&originWidth=1086&size=43820&status=done&style=none&width=543)
可以正常运行，nice
## References
[010editor手写PE文件](https://www.cnblogs.com/by-clark/p/9129135.html)
[手动增加PE节并修改oep](https://www.cnblogs.com/adylee/p/8780188.html)
