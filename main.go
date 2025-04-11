package main

import (
	"crypto/sha256"
	"crypto/sha512"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/docopt/docopt-go"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"

	_ "github.com/go-sql-driver/mysql"
)

const (
	defaultIterations = 100000
	defaultKeySize    = 32 // 256 bits
	guid              = "{9450BEF7-7D9F-4E4F-A18A-971D8681722D}"
)

type User struct {
	ID        string
	FirstName string
	LastName  string
	Email     string
}

// getPasswordHashSalt 计算 OnlyOffice 风格的 PBKDF2 盐值
// machineKey: 来自配置文件的 core.machinekey 值（如 "JCve93aUxzSr"）
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

// hashPassword 使用 PBKDF2 哈希密码
func hashPassword(password, salt string) string {
	hashBytes := pbkdf2.Key(
		[]byte(password),
		[]byte(salt),
		defaultIterations,
		defaultKeySize,
		sha256.New,
	)
	return hex.EncodeToString(hashBytes)
}

// getPasswordHash 计算最终的密码哈希
// 第一阶段：PBKDF2 hash + 第二阶段：SHA512 + Base64
func getPasswordHash(userID, password, machineKey string) string {
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

// updateUserPassword 更新指定用户的密码
func updateUserPassword(db *sql.DB, userID, newPassword, machineKey string) error {
	pwdhash := getPasswordHash(userID, newPassword, machineKey)

	// 使用事务确保数据一致性
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("事务开启失败: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.Exec("UPDATE core_usersecurity SET pwdhash = ? WHERE userid = ?", pwdhash, userID)
	if err != nil {
		return fmt.Errorf("更新密码失败: %w", err)
	}

	return tx.Commit()
}

// listUsers 获取所有用户信息
func listUsers(db *sql.DB) ([]User, error) {
	var users []User

	rows, err := db.Query("SELECT id, firstname, lastname, email FROM core_user")
	if err != nil {
		return nil, fmt.Errorf("查询用户失败: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.FirstName, &u.LastName, &u.Email); err != nil {
			return nil, fmt.Errorf("扫描用户数据失败: %w", err)
		}
		users = append(users, u)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历用户数据失败: %w", err)
	}

	return users, nil
}

// getUserInput 提示并读取用户输入（支持安全输入）
func getUserInput(prompt string, secure bool) (string, error) {
	fmt.Print(prompt)
	if secure {
		bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println() // 自动换行
		return string(bytePassword), err
	}

	var input string
	_, err := fmt.Scanln(&input)
	return input, err
}

// dbConfigFromArgs 根据命令行参数构建数据库连接字符串
func dbConfigFromArgs(args map[string]interface{}) string {
	return fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=true",
		args["--user"], args["--password"], args["--host"], args["--port"], args["--database"])
}

// validateUserExists 检查用户是否存在
func validateUserExists(db *sql.DB, userID string) (bool, error) {
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM core_user WHERE id = ?)", userID).Scan(&exists)
	return exists, err
}

func main() {
	// 命令行参数定义
	usage := `OnlyOffice 密码更新工具

Usage:
  onlyoffice-pwd-update [--host=<host>] [--port=<port>] [--user=<user>] [--password=<password>] 
                        [--database=<db>] [--machinekey=<key>]
  onlyoffice-pwd-update -h | --help

Options:
  -h --help           显示帮助信息
  --host=<host>       MySQL 主机 [default: localhost]
  --port=<port>       MySQL 端口 [default: 3306]
  --user=<user>       MySQL 用户名 [default: root]
  --password=<pwd>    MySQL 密码 [default: onlyoffice]
  --database=<db>     数据库名 [default: onlyoffice]
  --machinekey=<key>  机器密钥 [default: WIN-O26RHTFOIIG]`

	// 解析命令行参数
	args, err := docopt.ParseDoc(usage)
	if err != nil {
		log.Fatalf("参数解析失败: %v", err)
	}

	// 构建数据库连接配置
	dbConfig := dbConfigFromArgs(args)

	// 连接数据库
	db, err := sql.Open("mysql", dbConfig)
	if err != nil {
		log.Fatalf("数据库连接失败: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("数据库连接测试失败: %v", err)
	}

	// 获取并打印用户列表
	users, err := listUsers(db)
	if err != nil {
		log.Fatalf("获取用户列表失败: %v", err)
	}

	fmt.Println("\n用户列表：")
	for _, user := range users {
		fmt.Printf("ID: %s, 姓名: %s %s, 邮箱: %s\n", user.ID, user.FirstName, user.LastName, user.Email)
	}

	// 选择用户
	userID, err := getUserInput("\n输入要修改密码的用户ID: ", false)
	if err != nil {
		log.Fatalf("读取用户ID失败: %v", err)
	}

	// 验证用户是否存在
	exists, err := validateUserExists(db, userID)
	if err != nil {
		log.Fatalf("验证用户ID失败: %v", err)
	}
	if !exists {
		log.Fatal("错误：用户ID不存在")
	}

	// 密码输入验证
	newPassword, err := getUserInput("输入新密码: ", true)
	if err != nil {
		log.Fatalf("读取密码失败: %v", err)
	}

	if len(newPassword) < 8 {
		log.Fatal("错误：密码长度至少需要8个字符")
	}

	confirmPassword, err := getUserInput("再次输入新密码: ", true)
	if err != nil {
		log.Fatalf("读取确认密码失败: %v", err)
	}

	if newPassword != confirmPassword {
		log.Fatal("错误：两次密码不匹配")
	}

	// 获取机器密钥
	machineKey, _ := args["--machinekey"].(string)

	// 更新密码
	if err := updateUserPassword(db, userID, newPassword, machineKey); err != nil {
		log.Fatalf("密码更新失败: %v", err)
	}

	fmt.Printf("\n用户ID %s 的密码已安全更新\n", userID)
	// fmt.Printf("使用的机器密钥: %s\n", machineConstant)
}

