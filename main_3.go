package main

import (
	"golang.org/x/crypto/ssh"
	"time"
	"log"
	"os"
	"golang.org/x/crypto/ssh/terminal"
	"net"
	"strconv"
	"fmt"
	"encoding/json"
)


/**
远程执行交互式命令，比如 top ， 远程编辑一个文件，比如 vi /etc/nginx/nginx.conf
如果要支持交互式的命令，需要当前的terminal来接管远程的 PTY


有的服务器禁止 账号密码登录试探 则使用账号密码时会失败
 */

//使用私钥的方式登录服务器
func connectKey(user string, host string, port int) (*ssh.Session, error) {
	var (
		addr 			string
		auth 			[]ssh.AuthMethod
		clientConfig	*ssh.ClientConfig
		client			*ssh.Client
		session			*ssh.Session
		err				error
	)

	auth = make([]ssh.AuthMethod, 0)

	/********私钥验证的形式********/
	//利用私钥的形式
	privateKey := `-----BEGIN RSA PRIVATE KEY-----
私钥内容
-----END RSA PRIVATE KEY-----`
	key, err := ssh.ParsePrivateKey([]byte(privateKey))
	if err != nil {
		return nil, err
	}
	auth = append(auth, ssh.PublicKeys(key))
	/*******私钥验证的形式end******/

	clientConfig = &ssh.ClientConfig{
		User: user,
		Auth: auth,
		Timeout: 30 * time.Second,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	addr = host + ":" + strconv.Itoa(port)

	if client, err = ssh.Dial("tcp", addr, clientConfig); err != nil {
		return nil, err
	}

	if session, err = client.NewSession(); err != nil {
		return nil, err
	}

	return session, nil
}

//ssh连接远程服务器
/**
user string 默认 root用户
host string 远程服务器ip地址
port int 端口 默认 22
返回连接后的 session 和 error
 */
func connect(user string, host string, password string, port int) (*ssh.Session, error) {
	var (
		addr 			string
		auth 			[]ssh.AuthMethod
		clientConfig	*ssh.ClientConfig
		client			*ssh.Client
		session			*ssh.Session
		err				error
	)

	auth = make([]ssh.AuthMethod, 0)

	/********账号密码的形式********/
	//账号密码的形式
	auth = append(auth, ssh.Password(password))
	/********账号密码的形式end********/

	clientConfig = &ssh.ClientConfig{
		User: user,
		Auth: auth,
		Timeout: 30 * time.Second,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	addr = host + ":" + strconv.Itoa(port)

	if client, err = ssh.Dial("tcp", addr, clientConfig); err != nil {
		return nil, err
	}

	if session, err = client.NewSession(); err != nil {
		return nil, err
	}

	return session, nil
}




// 连接服务器所需信息的结构体
type Linker struct {
	Host 	 string `json:"host"`
	User 	 string `json:"user"`
	Port 	 int `json:"port"`
	AuthType int `json:"auth_type"` //标记验证 1：为密钥 2：密码
	Title 	 string `json:"title"`
}

var linkConfig Linker

//初始服务 匹配正确的服务器
func init() {
	//解析json服务器配置文件
	file, err := os.Open("config.conf")
	if err != nil {
		log.Fatalln("获取服务器配置文件config.conf失败：", err)
	}

	var config []Linker

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		log.Fatalln("解析服务器配置文件时出错：", err)
	}


	if len(os.Args)==1 {
		fmt.Println("请选择请要连接的服务器：")
		for k, val := range config {
			fmt.Println( strconv.Itoa(k+1) + "：" + val.Title)
		}

		os.Exit(0)
	}


	n, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatalln("请输入正确的服务器编号！！1 - " + strconv.Itoa(len(config)))
	}

	if n==0 || n>len(config) {
		log.Fatalln("请输入正确的服务器编号！！1 - " + strconv.Itoa(len(config)))
	}

	linkConfig = config[n-1]
}


func main() {

	var session *ssh.Session
	var err error

	if linkConfig.AuthType == 1 {
		session, err = connectKey(linkConfig.User, linkConfig.Host, linkConfig.Port)
	} else {
		session, err = connect(linkConfig.User, linkConfig.Host, "", linkConfig.Port)
	}
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	//返回标准输入对应的整数类型的unix文件描述符
	fd := int(os.Stdin.Fd())
	oldState, err := terminal.MakeRaw(fd)
	if err != nil {
		panic(err) //直接中断
	}
	defer terminal.Restore(fd, oldState)


	//重定向标准输入输出错误
	session.Stdin  = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	termWidth, termHeight, err := terminal.GetSize(fd)
	if err != nil {
		panic(err)
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:			1,
		ssh.TTY_OP_ISPEED:  1,
		ssh.TTY_OP_OSPEED:  14400,
	}

	if err := session.RequestPty("xterm-256color", termHeight, termWidth, modes); err != nil {
		log.Fatal(err)
	}

	/**
	session.Run("top") 方法 远程terminal执行玩命令后会退出并将远程的输出内容，重定向到当前终端上，调用退出
	 */
	//session.Run("top")


	/**
	session.Shell() session.Wait() shell()将远程terminal直接重定向到当前终端上，wait()可监测远程是否退出，若退出则本地也关闭退出
	 */
	err = session.Shell()
	if err != nil {
		log.Fatal(err)
	}

	err = session.Wait()
	if err != nil {
		log.Fatal(err)
	}

}
