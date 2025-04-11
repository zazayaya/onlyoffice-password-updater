# onlyoffice改密

## 使用

```shell
# machinekey value
grep core.machinekey WebStudio/web.appsettings.config
# mysql config
cat WebStudio/web.connections.config

# linux
# docker cp ./onlyoffice-password-updater onlyoffice-community-server:/root/
# docker exec -it onlyoffice-community-server bash
./onlyoffice-password-updater -h
./onlyoffice-password-updater \
  --host=onlyoffice-mysql-server \
  --user=onlyoffice_user \
  --password=onlyoffice_pass \
  --machinekey=JCve93aUxzSr

# windows
./onlyoffice-password-updater.exe -h
./onlyoffice-password-updater.exe --machinekey=JCve93aUxzSr

# 示例：
# ./onlyoffice-password-updater \
#   --host=onlyoffice-mysql-server \
#   --user=onlyoffice_user \
#   --password=onlyoffice_pass \
#   --machinekey=JCve93aUxzSr
# 
# 用户列表：
# ID: 41a54135-15e5-11f0-a6f7-0242ac120004, 姓名: Administrator , 邮箱: admin@local.com
# ID: 5ff4a605-a90e-4d48-b7a2-994048d6cbab, 姓名: zaza zhang, 邮箱: zaza@local.com
# 
# 输入要修改密码的用户ID: 5ff4a605-a90e-4d48-b7a2-994048d6cbab
# 输入新密码: 
# 再次输入新密码: 
# 
# 用户ID 5ff4a605-a90e-4d48-b7a2-994048d6cbab 的密码已安全更新
```

## 登陆测试

> 访问：http://ip/Auth.aspx

打开调试窗口，输入用户密码后，点击 “Auth.aspx?refererurl=%2fDefault.aspx”，负载里面包含：**passwordHash**

- js核心代码

  ```js
  // grep hashPassword onlyoffice/WebStudio/js/asc/core/common.js
  window.hashPassword = function (password, callback) {
      var size = ASC.Resources.Master.PasswordHashSize;
      var iterations = ASC.Resources.Master.PasswordHashIterations;
      var salt = ASC.Resources.Master.PasswordHashSalt;
  
      var bits = sjcl.misc.pbkdf2(password, salt, iterations);
      bits = bits.slice(0, size / 32);
      var hash = sjcl.codec.hex.fromBits(bits);
  
      callback(hash);
  };
  ```

- 控制台调试

  ```js
  // 直接控制台调试(核心获取：salt)
  console.log("size:", ASC.Resources.Master.PasswordHashSize);
  console.log("iterations:", ASC.Resources.Master.PasswordHashIterations);
  console.log("salt:", ASC.Resources.Master.PasswordHashSalt);
  // 调试
  var size = ASC.Resources.Master.PasswordHashSize;
  var iterations = ASC.Resources.Master.PasswordHashIterations;
  var salt = ASC.Resources.Master.PasswordHashSalt;
  var bits = sjcl.misc.pbkdf2("11111111", salt, iterations);
  bits = bits.slice(0, size / 32);
  var hash = sjcl.codec.hex.fromBits(bits);
  ```

## 网页密码hash算法

> 关键字：passwordHash
>
> https://github.com/search?q=repo%3AONLYOFFICE%2FCommunityServer passwordHash&type=code

- 加密算法

  ```cs
  // common/ASC.Common/Security/Cryptography/PasswordHasher.cs
  // 默认获取路径：grep core onlyoffice/WebStudio/web.appsettings.config
  PasswordHashSalt = (ConfigurationManagerExtension.AppSettings["core.password.salt"] ?? "").Trim();
  // 不存在就自动生成一个
  if (string.IsNullOrEmpty(PasswordHashSalt))
  {
      var salt = Hasher.Hash("{9450BEF7-7D9F-4E4F-A18A-971D8681722D}", HashAlg.SHA256);
  
      var PasswordHashSaltBytes = KeyDerivation.Pbkdf2(
                                         Encoding.UTF8.GetString(MachinePseudoKeys.GetMachineConstant()),
                                         salt,
                                         KeyDerivationPrf.HMACSHA256,
                                         PasswordHashIterations,
                                         PasswordHashSize / 8);
      PasswordHashSalt = BitConverter.ToString(PasswordHashSaltBytes).Replace("-", string.Empty).ToLower();
  }
  }
  
  //  MachinePseudoKeys.GetMachineConstant 算法
  // common/ASC.Common/Security/Cryptography/MachinePseudoKeys.cs
  // 默认通过 core.machinekey 进行计算
  ```

- go语言版本

  ```go
  package main
  
  import (
      "crypto/sha256"
      "encoding/hex"
      "fmt"
      "golang.org/x/crypto/pbkdf2"
  )
  
  const (
      defaultIterations = 100000
      defaultKeySize    = 32 // 256 bits
      guid              = "{9450BEF7-7D9F-4E4F-A18A-971D8681722D}"
  )
  
  // getPasswordHashSalt 计算 OnlyOffice 风格的 PBKDF2 盐值
  // machineKey: 来自配置文件的 core.machinekey 值（如 "JCve93aUxzSr"）
  // 必须与 ASC.Resources.Master.PasswordHashSalt 相同
  func getPasswordHashSalt(machineKey string) string {
      // 1. 生成初始盐基（固定GUID的SHA256哈希）
      initialSalt := sha256.Sum256([]byte(guid))
  
      // 2. 使用机器密钥和初始盐基进行PBKDF2派生
      saltBytes := pbkdf2.Key(
          []byte(machineKey), // 直接使用配置的machineKey
          initialSalt[:],
          defaultIterations,
          defaultKeySize,
          sha256.New,
      )
  
      // 3. 转为小写十六进制字符串（模拟C#的ToLower）
      return hex.EncodeToString(saltBytes)
  }
  
  func hashPassword(password, salt string) string {
      // 参数需与前端一致
      iterations := 100000
      keySize := 256 / 8 // 32字节
  
      // PBKDF2 哈希
      hashBytes := pbkdf2.Key(
          []byte(password),
          []byte(salt),
          iterations,
          keySize,
          sha256.New,
      )
      return hex.EncodeToString(hashBytes)
  }
  
  func main() {
      salt := getPasswordHashSalt("JCve93aUxzSr")
      password := "11111111"
      hash := hashPassword(password, salt)
      fmt.Println(hash) // 输出应与前端一致
  }
  ```

## 数据库密码算法

> https://blog.csdn.net/sierrak/article/details/144694928

- 数据库代码

  ```cs
  // common/ASC.Core.Common/Data/DbTenantService.cs
  var q = TenantsQuery(Exp.Empty)
                      .InnerJoin("core_user u", Exp.EqColumns("t.id", "u.tenant"))
                      .InnerJoin("core_usersecurity s", Exp.EqColumns("u.id", "s.userid"))
                      .Where("t.status", (int)TenantStatus.Active)
                      .Where("u.id", userId)
                      .Where("u.status", EmployeeStatus.Active)
                      .Where("u.removed", false)
                      .Where(Exp.Eq("s.pwdhash", GetPasswordHash(userId, passwordHash)));
  
  // GetPasswordHash: common/ASC.Core.Common/Data/DbBaseService.cs
  // 这里的 password 实际上是客户端生成的 passwordHash 值的回传，并不是明文密码
  protected static string GetPasswordHash(Guid userId, string password)
  {
      return Hasher.Base64Hash(password + userId + Encoding.UTF8.GetString(MachinePseudoKeys.GetMachineConstant()), HashAlg.SHA512);
  }
  ```

- golang版本

  ```go
  func getPasswordHash(userID, password, machineKey string) string {
  	// 第一阶段：SHA256哈希密码
  	salt := getPasswordHashSalt(machineKey)
  	hashPassword := hashPassword(password, salt)
  	
  	// console查看: console.log("salt:", ASC.Resources.Master.PasswordHashSalt);
  	// fmt.Printf("ASC.Resources.Master.PasswordHashSalt: %s\n", salt)
  	// fmt.Printf("passwordHash: %s\n", hashPassword)
  
  	// 第二阶段：组合并SHA512+Base64
  	combined := hashPassword + userID + machineKey
  	hash := sha512.Sum512([]byte(combined))
  	return base64.StdEncoding.EncodeToString(hash[:])
  }
  ```

## 编译使用

```shell
go build -o onlyoffice-password-updater main.go 
GOOS=windows GOARCH=amd64 go build -o onlyoffice-password-updater.exe main.go 

# ./onlyoffice-password-updater --host=onlyoffice-mysql-server --user=onlyoffice_user --password=onlyoffice_pass --machinekey=JCve93aUxzSr
# ./onlyoffice-password-updater.exe --machinekey=JCve93aUxzSr
```

