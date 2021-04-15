# PicoCTF-2021
> # Author: Stirring
> # Team: ζp33d_0∫_Ψ1m3
> # 2 Week with PicoCTF CTF

![picoCTF](https://user-images.githubusercontent.com/62060867/113077482-71fa9b00-91fb-11eb-8205-4e62a9ecdfc8.png)

# FORENSICS

> # 1. Information

* Hint: Look at the details of the file
* [cat.jpg](https://user-images.githubusercontent.com/62060867/113086781-8c894000-920c-11eb-91c8-09528c8a4551.jpg)


![164434195_123326646427510_4274251146342551561_n](https://user-images.githubusercontent.com/62060867/113085568-4e8b1c80-920a-11eb-8446-4a25cb0703eb.png)

* Hint: Look at the details of the file

* Hừm đầu tiên ta theo hint mà làm theo.
* Mình dùng [Metadata2go](https://www.metadata2go.com/) để check details of file ```jpg```

![download (8)](https://user-images.githubusercontent.com/62060867/113086117-3d8edb00-920b-11eb-92e1-21312fd5725a.png)


* Để ý ngay ```License cGljb0NURnt0aGVfbTN0YWRhdGFfMXNfbW9kaWZpZWR9``` trông như base64. Thử decode với [MultiSolver](https://geocaching.dennistreysa.de/multisolver/)

* So we got the flag: ```picoCTF{the_m3tadata_1s_modified}```

> # 2. Matryoshka doll

* Hint: Wait, you can hide files inside files? But how do you find them?
* [this](https://user-images.githubusercontent.com/62060867/113086809-9c088900-920c-11eb-920b-76133bd60ee4.jpg)

![164822421_862938537588742_559715876628647739_n](https://user-images.githubusercontent.com/62060867/113086596-1e447d80-920c-11eb-9766-b3018e78b7a4.png)

* Tiếp tục theo hint ```hide files inside files``` ta dùng lệnh ```binwalk``` để xem có file nào bị ẩn bên trong hay không

* Sau khi kiểm tra mình thấy có file đáng ngờ nên mình dùng lệnh ```binwalk -e dolls.jpg``` để lấy file

![164708049_814501092611206_8643528878716042788_n](https://user-images.githubusercontent.com/62060867/113088541-ffe08100-920f-11eb-85ed-c1a8dc32c3cd.png)


* Ta tiếp tục có thêm file ảnh khác. Ta tiếp tục lặp lại cho đến khi có file ```flag.txt```

![164495850_259303822527100_6687462875972873333_n](https://user-images.githubusercontent.com/62060867/113088537-fe16bd80-920f-11eb-96e8-b06f88526938.png)

So we got the flag: ```picoCTF{e3f378fe6c1ea7f6bc5ac2c3d6801c1f}```    


> # 3. Tunn3l v1s10n

* Hint: Weird that it won't display right...
* [file](https://github.com/Stirring16/PicoCTF-2021/files/6233718/tunn3l_v1s10n.zip)

![165618266_1901895733290813_6695979576279454617_n](https://user-images.githubusercontent.com/62060867/113089397-c872d400-9211-11eb-9523-a1b8b9db1866.png)

* Mở file không được. Thử check file header bằng ```HxD``` ta thấy đây là ```Corrupted BMP files```.

![165558825_3649769611800628_8677898799086586756_n](https://user-images.githubusercontent.com/62060867/113090946-1c32ec80-9215-11eb-9ff4-3b3b299c4955.png)


* Vì vậy mình đã search GG tìm cách fix. Dựa theo [bài này](https://asecuritysite.com/forensics/bmp?file=activated.bmp) mình thấy file bị sai ở một số Byte:
* ``` 
      Bytes 3-6 (Images Size) 0000073E
      Bytes 11-14 (Image offset) 00000036
      Bytes 15-18 (size of BITMAPINFOHEADER structure, must be 40 [0x28]) 00000028
  ```
 

* ```
   8E 26 2C -> 3E 07 00
   BA D0 -> 36 00
   BA D0 -> 28 00```

* Fix xong ta nhận được gì :D
![164311317_795515658035314_3459416398182503111_n](https://user-images.githubusercontent.com/62060867/113092863-03c4d100-9219-11eb-878b-2b1f7cb386e0.png)



* ```notaflag{sorry}``` Ok Its fine 
* Tới đây mình tốn rất nhiều time để tìm ra hướng làm tiếp theo.
* Vào một ngày đẹp trời một tia sang hiện ra mình nhận ra có thể fix ```imageHeight``` ở ```Bytes 23-26``` 

```42 4D 3E 07 00 00 00 00 00 00 36 00 00 00 28 00 00 00 6E 04 00 00 32 01 00 00 01 00 18 00 00 00```

Vì đã thử nâng từ ```32 01 ->> 32 02``` và bức ảnh đã hiện ra thêm :D

![164064190_520478316012426_6514811059129697675_n](https://user-images.githubusercontent.com/62060867/113094223-82bb0900-921b-11eb-849b-9c8e1665ecca.png)

Tiếp thôi ``` 32 02 -> 32 03 ```

![download (11)](https://user-images.githubusercontent.com/62060867/113094254-8babda80-921b-11eb-9d2d-fbcc3e9f229b.png)

So we got the flag: picoCTF{qu1t3_a_v13w_2020}

> # 4. Wireshark doo dooo do doo...

[shark1.zip](https://github.com/Stirring16/PicoCTF-2021/files/6233966/shark1.zip)

![164688110_301630531515610_875587652764779898_n](https://user-images.githubusercontent.com/62060867/113094641-3de3a200-921c-11eb-8926-464d7bb8bd1f.png)

* Open ```Wireshark``` to see ```shark1.pcapng```
* Phân tích các luồng của TCP và HTTP
* Hầu hết traffic đều được mã hóa Kerberos, và có một packet chứa ```text/html```

![download](https://user-images.githubusercontent.com/62060867/113904417-429bed80-97fc-11eb-861c-248ddc802937.png)

* Follow ```HTTP stream 537``` ta có một đoạn mã hóa 

![168911334_732651690949977_2141637927140596849_n](https://user-images.githubusercontent.com/62060867/113904780-a4f4ee00-97fc-11eb-8f95-a186b5bd2b60.png)

 ```Gur synt vf cvpbPGS{c33xno00_1_f33_h_qrnqorrs}```
 
* Quăng lên ```Multisolves``` 

![167127681_730852357587066_5881762056687373651_n](https://user-images.githubusercontent.com/62060867/113905270-29477100-97fd-11eb-91f4-b7f5d37cbf47.png)

So we got the flag :D

> # 5. Trivial Flag Transfer Protocol

* Hint: What are some other ways to hide data?
* [flag]()

![168837760_436928107595325_5013312693557380805_n](https://user-images.githubusercontent.com/62060867/113905908-d91cde80-97fd-11eb-9179-42550ceb4202.png)

* Đầu tiên mở ```Wireshark``` xem ta có gì

![169297543_473903980714668_6282967211736740508_n](https://user-images.githubusercontent.com/62060867/113906705-b8a15400-97fe-11eb-9a48-7dc4df6f6b18.png)

* TFTP hmmm.... TFTP là viết tắt của Trivial File Transfer Protocol, là 1 giao thức truyền file đơn giản. Hmm để xem ta có gì nào, select: ```File -> Export Objects -> TFTP``` 

![download (1)](https://user-images.githubusercontent.com/62060867/113907116-2f3e5180-97ff-11eb-9e4a-de36bc78cf6b.png)

* Save all và check các file

* Đầu tiên check 2 file ```Instruction.txt and Plan```

![167157233_460315035422327_5401500803605554920_n](https://user-images.githubusercontent.com/62060867/113908594-eab3b580-9800-11eb-9484-a80752695aef.png)

* ROT13?? Yep, Decode Rot13 ta được:

```
TFTP DOESNT ENCRYPT OUR TRAFFIC SO WE MUST DISGUISEOUR FLAG TRANSFER. FIGURE OUT AWAY TO HIDE THE FLAG AND I WILL CHECK BACK FOR THE PLAN

   I USED THE PROGRAM AND HID IT WITH -DUEDILIGENCE. CHECK OUT THE PHOTOS
```
   
 * Tiếp tục check file .Deb
 
 ![168457542_1898200430343612_6065637012453202765_n](https://user-images.githubusercontent.com/62060867/113955327-b6161d00-9845-11eb-9954-1843d24e2dbd.png)

* Steghide? Theo hint thì mình đoán được Steghide là công cụ sử dụng để hide data trong 3 file bmp.

* Việc tiếp theo chỉ cần tìm ```Passphrase```. Nhìn lại đoạn decode trên ```HID IT WITH -DUEDILIGENCE```, có lẽ đây là Passphrase. 
* Thử DUEDILIGENCE với từng file bmp và....

![170066167_2927712374140759_3640017285400063701_n](https://user-images.githubusercontent.com/62060867/113955949-e6aa8680-9846-11eb-9b27-40eaf6bf0f50.png)

So we got the flag

> # 6. Wireshark twoo twooo two twoo...
Hint1: Did you really find _the_ flag?
Hint2: Look for traffic that seems suspicious.
[shark2.pcapng]()

![168821344_959773858208974_7624007569779743192_n](https://user-images.githubusercontent.com/62060867/113959063-6129d500-984c-11eb-8637-fe47a5b43361.png)

* Sau khi phân tích và kiểm tra tất cả Stream, mình thấy có rất nhiều Flag giả gây nhiễu
* Ở ```HTTP Object list``` có 89 file flag, mình thử random submit thử vài Flag nhưng vô ích.

![168950366_778626423072533_4084078386040631460_n](https://user-images.githubusercontent.com/62060867/113959734-971b8900-984d-11eb-914a-e8b26bd33729.png)

* Check tiếp DNS có rất nhiều Domain ```reddshrimpandherring.com``` chứa encoded flag bằng base64, thử decode bằng submit nhưng vẫn incorrect 

![download (2)](https://user-images.githubusercontent.com/62060867/113961542-6db02c80-9850-11eb-89c9-381ea7805e55.png)

* Sau đó mình nhận thấy các DNS cuối cùng thay đối Destination từ ```8.8.8.8``` đến ```18.217.1.57``` và có domain là ```fQ==reddshrimpandherring.com```
* Dùng filter để lọc các Destination ```18.217.1.57``` với filter ```ip.src == 18.217.1.57``` ta sẽ thấy 5 Domain được query response :


```
      cGljb0NU.reddshrimpandherring.com
      RnTkbnNf.reddshrimpandherring.com
      M3hmMWxf.reddshrimpandherring.com
      ZnR3X2Rl.reddshrimpandherring.com
      YWRiZWVm.reddshrimpandherring.com
  ```
* Ta được ```cGljb0NURnTkbnNfM3hmMWxfZnR3X2RlYWRiZWVm```
* Decode bằng base64 ta có ngay flag

 So we got the flag: ```picoCTF{tns_3xf1l_ftw_deadbeef}```


> # 7. MacroHard WeakEdge

[Forensics is fun](https://github.com/Stirring16/PicoCTF-2021/files/6303416/Forensics.is.fun.zip)

![169148315_5377732578965822_2297541516591196728_n](https://user-images.githubusercontent.com/62060867/114546958-fb907b00-9c87-11eb-8dcf-333f4d117c78.png)

* Challenge này cho một file Powerpoint, mình đã mở thử xem và chả có gì hơn ngoài dòng chữ ```Forensics is fun```
* Sau khi tìm hiểu thì file PowerPoint thật ra là một file zip, nên mình đã unzip xem có gì bên trong

```
kali㉿kali)-[~/Desktop]
└─$ file Forensics\ is\ fun.pptm 
Forensics is fun.pptm: Microsoft PowerPoint 2007+
                                                                                 
┌──(kali㉿kali)-[~/Desktop]
└─$ unzip Forensics\ is\ fun.pptm                          
Archive:  Forensics is fun.pptm
  inflating: [Content_Types].xml     
  inflating: _rels/.rels             
  inflating: ppt/presentation.xml    
  inflating: ppt/slides/_rels/slide46.xml.rels  
  inflating: ppt/slides/slide1.xml   
  inflating: ppt/slides/slide2.xml   
  inflating: ppt/slides/slide3.xml   
  inflating: ppt/slides/slide4.xml   
  inflating: ppt/slides/slide5.xml   
  inflating: ppt/slides/slide6.xml   
  inflating: ppt/slides/slide7.xml   
  inflating: ppt/slides/slide8.xml   
  inflating: ppt/slides/slide9.xml   
  inflating: ppt/slides/slide10.xml  
  inflating: ppt/slides/slide11.xml  
  inflating: ppt/slides/slide12.xml  
  inflating: ppt/slides/slide13.xml  
  inflating: ppt/slides/slide14.xml  
  inflating: ppt/slides/slide15.xml  
  inflating: ppt/slides/slide16.xml  
  inflating: ppt/slides/slide17.xml  
  inflating: ppt/slides/slide18.xml  
  inflating: ppt/slides/slide19.xml  
  inflating: ppt/slides/slide20.xml  
  inflating: ppt/slides/slide21.xml  
  inflating: ppt/slides/slide22.xml  
  inflating: ppt/slides/slide23.xml  
  inflating: ppt/slides/slide24.xml  
  inflating: ppt/slides/slide25.xml  
  inflating: ppt/slides/slide26.xml  
  inflating: ppt/slides/slide27.xml  
  inflating: ppt/slides/slide28.xml  
  inflating: ppt/slides/slide29.xml  
  inflating: ppt/slides/slide30.xml  
  inflating: ppt/slides/slide31.xml  
  inflating: ppt/slides/slide32.xml  
  inflating: ppt/slides/slide33.xml  
  inflating: ppt/slides/slide34.xml  
  inflating: ppt/slides/slide35.xml  
  inflating: ppt/slides/slide36.xml  
  inflating: ppt/slides/slide37.xml  
  inflating: ppt/slides/slide38.xml  
  inflating: ppt/slides/slide39.xml  
  inflating: ppt/slides/slide40.xml  
  inflating: ppt/slides/slide41.xml  
  inflating: ppt/slides/slide42.xml  
  inflating: ppt/slides/slide43.xml  
  inflating: ppt/slides/slide44.xml  
  inflating: ppt/slides/slide45.xml  
  inflating: ppt/slides/slide46.xml  
  inflating: ppt/slides/slide47.xml  
  inflating: ppt/slides/slide48.xml  
  inflating: ppt/slides/slide49.xml  
  inflating: ppt/slides/slide50.xml  
  inflating: ppt/slides/slide51.xml  
  inflating: ppt/slides/slide52.xml  
  inflating: ppt/slides/slide53.xml  
  inflating: ppt/slides/slide54.xml  
  inflating: ppt/slides/slide55.xml  
  inflating: ppt/slides/slide56.xml  
  inflating: ppt/slides/slide57.xml  
  inflating: ppt/slides/slide58.xml  
  inflating: ppt/slides/_rels/slide47.xml.rels  
  inflating: ppt/slides/_rels/slide48.xml.rels  
  inflating: ppt/slides/_rels/slide49.xml.rels  
  inflating: ppt/slides/_rels/slide50.xml.rels  
  inflating: ppt/slides/_rels/slide32.xml.rels  
  inflating: ppt/slides/_rels/slide52.xml.rels  
  inflating: ppt/slides/_rels/slide53.xml.rels  
  inflating: ppt/slides/_rels/slide54.xml.rels  
  inflating: ppt/slides/_rels/slide55.xml.rels  
  inflating: ppt/slides/_rels/slide56.xml.rels  
  inflating: ppt/slides/_rels/slide57.xml.rels  
  inflating: ppt/slides/_rels/slide58.xml.rels  
  inflating: ppt/slides/_rels/slide51.xml.rels  
  inflating: ppt/slides/_rels/slide13.xml.rels  
  inflating: ppt/_rels/presentation.xml.rels  
  inflating: ppt/slides/_rels/slide1.xml.rels  
  inflating: ppt/slides/_rels/slide2.xml.rels  
  inflating: ppt/slides/_rels/slide3.xml.rels  
  inflating: ppt/slides/_rels/slide4.xml.rels  
  inflating: ppt/slides/_rels/slide5.xml.rels  
  inflating: ppt/slides/_rels/slide6.xml.rels  
  inflating: ppt/slides/_rels/slide7.xml.rels  
  inflating: ppt/slides/_rels/slide8.xml.rels  
  inflating: ppt/slides/_rels/slide9.xml.rels  
  inflating: ppt/slides/_rels/slide10.xml.rels  
  inflating: ppt/slides/_rels/slide11.xml.rels  
  inflating: ppt/slides/_rels/slide12.xml.rels  
  inflating: ppt/slides/_rels/slide14.xml.rels  
  inflating: ppt/slides/_rels/slide15.xml.rels  
  inflating: ppt/slides/_rels/slide16.xml.rels  
  inflating: ppt/slides/_rels/slide17.xml.rels  
  inflating: ppt/slides/_rels/slide18.xml.rels  
  inflating: ppt/slides/_rels/slide19.xml.rels  
  inflating: ppt/slides/_rels/slide20.xml.rels  
  inflating: ppt/slides/_rels/slide21.xml.rels  
  inflating: ppt/slides/_rels/slide22.xml.rels  
  inflating: ppt/slides/_rels/slide23.xml.rels  
  inflating: ppt/slides/_rels/slide24.xml.rels  
  inflating: ppt/slides/_rels/slide25.xml.rels  
  inflating: ppt/slides/_rels/slide26.xml.rels  
  inflating: ppt/slides/_rels/slide27.xml.rels  
  inflating: ppt/slides/_rels/slide28.xml.rels  
  inflating: ppt/slides/_rels/slide29.xml.rels  
  inflating: ppt/slides/_rels/slide30.xml.rels  
  inflating: ppt/slides/_rels/slide31.xml.rels  
  inflating: ppt/slides/_rels/slide33.xml.rels  
  inflating: ppt/slides/_rels/slide34.xml.rels  
  inflating: ppt/slides/_rels/slide35.xml.rels  
  inflating: ppt/slides/_rels/slide36.xml.rels  
  inflating: ppt/slides/_rels/slide37.xml.rels  
  inflating: ppt/slides/_rels/slide38.xml.rels  
  inflating: ppt/slides/_rels/slide39.xml.rels  
  inflating: ppt/slides/_rels/slide40.xml.rels  
  inflating: ppt/slides/_rels/slide41.xml.rels  
  inflating: ppt/slides/_rels/slide42.xml.rels  
  inflating: ppt/slides/_rels/slide43.xml.rels  
  inflating: ppt/slides/_rels/slide44.xml.rels  
  inflating: ppt/slides/_rels/slide45.xml.rels  
  inflating: ppt/slideMasters/slideMaster1.xml  
  inflating: ppt/slideLayouts/slideLayout1.xml  
  inflating: ppt/slideLayouts/slideLayout2.xml  
  inflating: ppt/slideLayouts/slideLayout3.xml  
  inflating: ppt/slideLayouts/slideLayout4.xml  
  inflating: ppt/slideLayouts/slideLayout5.xml  
  inflating: ppt/slideLayouts/slideLayout6.xml  
  inflating: ppt/slideLayouts/slideLayout7.xml  
  inflating: ppt/slideLayouts/slideLayout8.xml  
  inflating: ppt/slideLayouts/slideLayout9.xml  
  inflating: ppt/slideLayouts/slideLayout10.xml  
  inflating: ppt/slideLayouts/slideLayout11.xml  
  inflating: ppt/slideMasters/_rels/slideMaster1.xml.rels  
  inflating: ppt/slideLayouts/_rels/slideLayout1.xml.rels  
  inflating: ppt/slideLayouts/_rels/slideLayout2.xml.rels  
  inflating: ppt/slideLayouts/_rels/slideLayout3.xml.rels  
  inflating: ppt/slideLayouts/_rels/slideLayout4.xml.rels  
  inflating: ppt/slideLayouts/_rels/slideLayout5.xml.rels  
  inflating: ppt/slideLayouts/_rels/slideLayout6.xml.rels  
  inflating: ppt/slideLayouts/_rels/slideLayout7.xml.rels  
  inflating: ppt/slideLayouts/_rels/slideLayout8.xml.rels  
  inflating: ppt/slideLayouts/_rels/slideLayout9.xml.rels  
  inflating: ppt/slideLayouts/_rels/slideLayout10.xml.rels  
  inflating: ppt/slideLayouts/_rels/slideLayout11.xml.rels  
  inflating: ppt/theme/theme1.xml    
 extracting: docProps/thumbnail.jpeg  
  inflating: ppt/vbaProject.bin      
  inflating: ppt/presProps.xml       
  inflating: ppt/viewProps.xml       
  inflating: ppt/tableStyles.xml     
  inflating: docProps/core.xml       
  inflating: docProps/app.xml        
  inflating: ppt/slideMasters/hidden  
```

* Để ý dòng có một file đáng ngờ ```ppt/slideMasters/hidden```
``` 
──(kali㉿kali)-[~/Desktop/ppt/slideMasters]
└─$ cat hidden          
Z m x h Z z o g c G l j b 0 N U R n t E M W R f d V 9 r b j B 3 X 3 B w d H N f c l 9 6 M X A 1 f Q   
```
* Decode ta có ngay flag
So we got the flag: ```picoCTF{D1d_u_kn0w_ppts_r_z1p5}```

> # 8. Disk, disk, sleuth!

hint: 1.Have you ever used `file` to determine what a file was?
      2.Relevant terminal-fu in picoGym: https://play.picoctf.org/practice/challenge/85
      3.Mastering this terminal-fu would enable you to find the flag in a single command: https://play.picoctf.org/practice/challenge/48
      4.Using your own computer, you could use qemu to boot from this disk!
     
![171704512_450224019375708_2686701168749791738_n](https://user-images.githubusercontent.com/62060867/114551174-3a74ff80-9c8d-11eb-9895-05d78a54b63a.png)

* Nhìn hint có vẻ hoành tráng nhưng chỉ cần dùng ```srch_strings``` và ``` grep picoCTF``` là ra thôi.

So we got the flag: 


> # 9. Disk, disk, sleuth! II
hint: 1.The sleuthkit has some great tools for this challenge as well.
      2.Sleuthkit docs here are so helpful: TSK Tool Overview
      3.This disk can also be booted with qemu!
     
![170290969_1827711787407617_7564603466930732663_n](https://user-images.githubusercontent.com/62060867/114552393-c20f3e00-9c8e-11eb-9649-aaa92130a917.png)

* Theo như Description thì flag nằm trong file ```down-at-the-botton.txt``` vì vậy mục tiêu là kiếm được file đó
* Thử với ```Qemu``` để tìm file 

So we got the flag: 


> # 10. MilkSlap
hint: Look at the problem category

![170680396_295053755557520_6097964404318094558_n](https://user-images.githubusercontent.com/62060867/114587607-0959f680-9cb0-11eb-915c-8d37617c4c45.png)

* Bài này cho ta 1 đường link qua icon ly sữa [🥛](http://mercury.picoctf.net:7585/) 

 ![image](https://user-images.githubusercontent.com/62060867/114588905-61452d00-9cb1-11eb-929a-534f88f8f902.png)
 
* Một file Gif. Check source nào
 
 
* Có một file ```concat_v.png``` trong source, save về và check file ảnh.
![image](https://user-images.githubusercontent.com/62060867/114691870-4ff83100-9d42-11eb-9d42-abc9f59b5a40.png)

* Mình dùng ```zsteg``` và....
```
┌──(kali㉿kali)-[~/Desktop]
└─$ zsteg concat_v.png 
imagedata           .. text: "\n\n\n\n\n\n\t\t"
b1,b,lsb,xy         .. text: "picoCTF{imag3_m4n1pul4t10n_sl4p5}\n"
b1,bgr,lsb,xy       .. <wbStego size=9706075, data="\xB6\xAD\xB6}\xDB\xB2lR\x7F\xDF\x86\xB7c\xFC\xFF\xBF\x02Zr\x8E\xE2Z\x12\xD8q\xE5&MJ-X:\xB5\xBF\xF7\x7F\xDB\xDFI\bm\xDB\xDB\x80m\x00\x00\x00\xB6m\xDB\xDB\xB6\x00\x00\x00\xB6\xB6\x00m\xDB\x12\x12m\xDB\xDB\x00\x00\x00\x00\x00\xB6m\xDB\x00\xB6\x00\x00\x00\xDB\xB6mm\xDB\xB6\xB6\x00\x00\x00\x00\x00m\xDB", even=true, mix=true, controlbyte="[">               
b2,r,lsb,xy         .. file: SoftQuad DESC or font file binary
b2,r,msb,xy         .. file: VISX image file
b2,g,lsb,xy         .. file: VISX image file
b2,g,msb,xy         .. file: SoftQuad DESC or font file binary - version 15722
b2,b,msb,xy         .. text: "UfUUUU@UUU"
b4,r,lsb,xy         .. text: "\"\"\"\"\"#4D"
b4,r,msb,xy         .. text: "wwww3333"
b4,g,lsb,xy         .. text: "wewwwwvUS"
b4,g,msb,xy         .. text: "\"\"\"\"DDDD"
b4,b,lsb,xy         .. text: "vdUeVwweDFw"
b4,b,msb,xy         .. text: "UUYYUUUUUUUU"
```
* So we got the flag


> # 10. Sufing the Waves
hint: Music is cool, but what other kinds of waves are there?
hint: Look deep below the surface

![image](https://user-images.githubusercontent.com/62060867/114699297-4ffc2f00-9d4a-11eb-83df-ea5b8cd33de0.png)

* Idea của bài này: 
```
1. Lấy các giá trị bằng scipy.wavfile.io.read ()
2. Ta sẽ nhận thấy tất cả các giá trị đều lớn hơn một chút so với bội số của 500
3. Chúng ta có thể chia cho 500 để đơn giản hóa các giá trị
4. Sau khi chia, các giá trị nằm trong khoảng từ 2 đến 17, là 16 giá trị
5. Trừ 2 từ mỗi giá trị, vì vậy nó trở thành 0 thành 15
6. Cho 10, 11, 12, 13, 14, 15, thay đổi thành a, b, c, d, e, f
7. In tất cả các giá trị bây giờ trong một chuỗi lớn
8. Chuyển đổi chuỗi thành ascii
9. Wow! 

```

```
┌──(kali㉿kali)-[~/Desktop]
└─$ python3 waves.py                       
#!/usr/bin/env python3
import numpy as np
from scipy.io.wavfile import write
from binascii import hexlify
from random import random

with open('generate_wav.py', 'rb') as f:
        content = f.read()
        f.close()

# Convert this program into an array of hex values
hex_stuff = (list(hexlify(content).decode("utf-8")))

# Loop through the each character, and convert the hex a-f characters to 10-15
for i in range(len(hex_stuff)):
        if hex_stuff[i] == 'a':
                hex_stuff[i] = 10
        elif hex_stuff[i] == 'b':
                hex_stuff[i] = 11
        elif hex_stuff[i] == 'c':
                hex_stuff[i] = 12
        elif hex_stuff[i] == 'd':
                hex_stuff[i] = 13
        elif hex_stuff[i] == 'e':
                hex_stuff[i] = 14
        elif hex_stuff[i] == 'f':
                hex_stuff[i] = 15

        # To make the program actually audible, 100 hertz is added from the beginning, then the number is multiplied by
        # 500 hertz
        # Plus a cheeky random amount of noise
        hex_stuff[i] = 1000 + int(hex_stuff[i]) * 500 + (10 * random())


def sound_generation(name, rand_hex):
        # The hex array is converted to a 16 bit integer array
        scaled = np.int16(np.array(hex_stuff))
        # Sci Pi then writes the numpy array into a wav file
        write(name, len(hex_stuff), scaled)
        randomness = rand_hex


# Pump up the music!
# print("Generating main.wav...")
# sound_generation('main.wav')
# print("Generation complete!")

# Your ears have been blessed
# picoCTF{mU21C_1s_1337_6a936af2}

```

So we got the flag

> # 12. Very very very Hidden

* Hint: I believe you found something, but are there any more subtle hints as random queries?
* Hint: The flag will only be found once you reverse the hidden message.

![image](https://user-images.githubusercontent.com/62060867/114699919-17a92080-9d4b-11eb-8e29-d83147d95bd1.png)

* Đầu tiên mọi khi check ```Object of HTTP``` có gì không

![image](https://user-images.githubusercontent.com/62060867/114833578-f2bfb680-9df9-11eb-9639-a142bff8bb3e.png)

> Yeah we have 2 ```duck.png```
> favicon.ico chỉ là icon
> NothingSus chắc là nothing thôi.
> The %5c one is empty

* Mình đã thử kiểm tra 2 bức hình nhưng không có gì, nhưng có 2 bức hình rất khả nghi. Tiếp tục check DNS, mình thấy được user đã làm gì đó thông qua:
```
1. He go to google
2. From google he go to github
3. Then go to microsoft
4. Login to  microsoft
5. And go to powershell.
```
* Hmm theo như mình dự đoán, có lẻ user đã lên github để tìm tool nào đó trên sử dụng trên powershell. Search trên GG tìm thử đó là gì.
* Sau khi tìm kiếm mình phát hiện được một tool có khả năng user đã sử dụng là: [Extract-PSIamge](https://github.com/imurasheen/Extract-PSImage) (A tool to extract Powershell script from PNG image generated by Invoke-PSImage.)








      























   
   
























