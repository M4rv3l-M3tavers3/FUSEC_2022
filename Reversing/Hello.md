- Challenge này có 1 file đính kèm là file thực thi.
  
  [hello.exe](https://github.com/M4rv3l-M3tavers3/FUSEC_2022/blob/main/Reversing/hello.exe)

Mình sử dụng IDA PRO để phân tích file này, mình sử dụng chức năng generate pseudo-code của IDA để đọc cho dễ hiểu:

![image](https://user-images.githubusercontent.com/93731698/195073225-c5232225-15de-46ca-bde7-1dadbcdac4a6.png)

Như thói quen thường dùng, mình `Shift + F12` để scan tất cả string trong file xem có gì không và dĩ nhiên chả có gì đặc biệt cho lắm.

![image](https://user-images.githubusercontent.com/93731698/195073698-4254d495-e726-4c74-af4f-44905c85e77e.png)

- Sự khác biệt khi mình vô hàm check(std::string) và thấy nghi ngờ `unk_472040` nên ấn thử vô 
![image](https://user-images.githubusercontent.com/93731698/195155944-f6341e7f-fe18-4bf2-bf96-bf44e4d0cb4b.png)

- Và mình thấy một loại các string đang bị mã hóa. Lúc này khá nghi ngờ đây chính là flag nên mình đã thử một chút. 

![image](https://user-images.githubusercontent.com/93731698/195156055-0bb2aba0-734c-4768-976a-7a2174487d0f.png)



 ![image](https://user-images.githubusercontent.com/93731698/195154030-1a45a581-97b7-480e-8ec0-8b03b03dce8c.png)

- Dựa vào dòng 19 và 20 cộng thêm ta đã biết format của flag là `FUSec{}` nên test thử với vài chữ đầu FUS


```python
 print(hex(4919*((ord('F') ^ 0x19) + 145)%255 & 0xFF))
 print(hex(4919*((ord('U') ^ 0x19) + 145)%255 & 0xFF))
 print(hex(4919*((ord('S') ^ 0x19) + 145)%255 & 0xFF))
```
![image](https://user-images.githubusercontent.com/93731698/195150235-716244ce-3d6e-40f8-958e-452e23d699f0.png)


- Thấy kết quả lần lượt là 0xa5, 0x22 và 0x8d đúng với 3 byte đầu xem trong Hex View-1 được thêm vào đầu tiên của mảng v4. Từ đó có thể chắc chắn đây chính là mấu chốt để lấy lại được flag. Từ đó có thể viết lại code để Reverse ra được flag.

### $Solution

```python
import string 
ENCRYPT= [
165, 34, 141, 16, 123, 132, 68, 16, 183, 167, 90, 230, 216, 93, 90, 216, 109, 249, 238, 35, 109, 109, 93, 142, 183, 197, 68, 90, 68, 167, 16 ,175, 238, 35, 197, 197, 197, 197, 183 ,238 ,238 ,249 ,216 ,90 ,68, 183, 216 ,230, 216, 230, 197, 35 ,93 ,249, 93, 230, 90 ,238 ,16 ,216, 175, 109, 68 ,249, 93, 142, 68, 68, 167, 93, 25]

flag=""

for i in range(len(ENCRYPT)):
    for c in string.printable:
        if 4919 * ((ord(c) ^ 0x19) + 145) % 255  == ENCRYPT[len(flag)]:
            flag += c
            break
            
print(flag)

```

- Sau đó trong vòng lặp while chúng ta đang brute-force các giá trị ascii của tất cả các kí tự và thỏa mãn tất cả các biểu thức trong code ban đầu để chúng bằng với giá trị hex của hàm v4 cần so sánh.
