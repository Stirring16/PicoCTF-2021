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
* Phân tích các luồng của TCP và HTTP,















