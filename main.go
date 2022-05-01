package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"
	acc "web/util"

	sdk "github.com/Conflux-Chain/go-conflux-sdk"
	"github.com/Conflux-Chain/go-conflux-sdk/types"
	"github.com/Conflux-Chain/go-conflux-sdk/types/cfxaddress"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/pkg/errors"
)

var HalfPrvDataPostclient *http.Client
var pukCa *rsa.PublicKey
var cfxclientRPC *sdk.Client
var Contract string = "cfxtest:accuhsxvt2t2871zhcjvw7pcpc8t2h593arztr2xh2" //测试网合约已验证
var From string = "cfxtest:aapfnh9vb8eycv4p2a9ydb2h19xn8abj2aberhvkhh"
var Contract_cfxaddress cfxaddress.Address
var From_cfxaddress cfxaddress.Address
var ABI []byte

type SignRequist_Message struct {
	Account      string `json:"account"`
	Secret       string `json:"secret"`
	Phone        string `json:"phone"`
	OpenID       string `json:"openid"`
	Time         int64  `json:"time"`
	Token        string `json:"token"`
	UnSignTxJson []byte `json:"unsigntxjson"`
	From         string `json:"from"`
	PaymentPass  string `json:"paymentpass"`
	ChainType    string `json:"chaintype"`
}

var testAccount string = "31c681bcb34c1457ab5b1521c340468ce106dfc6592bac55fb68f76994130d66"
var testSecrect string = "8d0f0b25c236af70c4980bea261b154745ccfba25e5683ef100a9e05b0922e88"
var testPhne string = "10101010101"
var testOpenID string = "951"

func main() {
	//注册一个Jugugu账号 https://testnet.jugugu.cn

	//加载ABI文件
	LoadABIJSON("ERC721.abi")
	initClient()
	InitRASPuk()
	InitCFXClient()
	TestSignTx()
}

////////////
func TestSignTx() {
	Contract_cfxaddress = cfxaddress.MustNewFromBase32(Contract)
	From_cfxaddress = cfxaddress.MustNewFromBase32(From)
	comm_addrss := From_cfxaddress.MustGetCommonAddress()
	var nfturi string = "https://starbit.oss-cn-shanghai.aliyuncs.com/api/zverse/metadata/5000.json"
	utx, err := CreateUnsignedTx(From_cfxaddress, Contract_cfxaddress, ABI, "awardItem", &comm_addrss, &nfturi)
	if err != nil {
		panic(err)
	} else {
		fmt.Println(utx)
	}
	fmt.Println(utx.ChainID)
	UnsignedTxbuff, err := json.Marshal(utx)
	if err != nil {
		panic(err)
	}
	//去jugugu请求签名
	paymentpass := "11a51aa0033b467d5984"
	rowData, err := SignTxDataPost("https://testnet.jugugu.cn", "Jugugu_FastSignTx", testAccount, testSecrect, testPhne, testOpenID, UnsignedTxbuff, From, paymentpass, "cfx")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(rowData))
	//发送交易
	txhash, err := cfxclientRPC.SendRawTransaction(rowData)
	if err != nil {
		panic(err)
	}
	fmt.Println("交易hash:", txhash.String())
}

////////////

func RegByPrk() {

}
func LoadABIJSON(abiname string) {
	fjson, err := os.Open("ERC721.abi")
	if err != nil {
		fmt.Println(err, "abi open error!")
	}
	var json_buff []byte = make([]byte, 10000000)
	defer fjson.Close()
	cont, _ := fjson.Read(json_buff)
	json_buff = json_buff[:cont]
	fjson.Close()
	ABI = json_buff
}
func initClient() {
	HalfPrvDataPostclient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: (&net.Dialer{
				Timeout:   60 * time.Second,
				KeepAlive: 60 * time.Second,
			}).DialContext,
			MaxIdleConns:          4096,
			IdleConnTimeout:       300 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}
func InitRASPuk() {
	fjson, err := os.Open("Signpublic.pem")
	if err != nil {
		fmt.Println(err, "Signpublic open error!")
	}
	var json_buff []byte = make([]byte, 1000000)
	defer fjson.Close()
	cont, _ := fjson.Read(json_buff)
	json_buff = json_buff[:cont]
	fjson.Close()
	block, _ := pem.Decode(json_buff)
	// fmt.Println(block)
	//3. 使用x509将编码之后的私钥解析出来
	publicKey, err3 := x509.ParsePKIXPublicKey(block.Bytes)
	if err3 != nil {
		panic(err3)
	}
	pukCa = publicKey.(*rsa.PublicKey)
}
func InitCFXClient() {
	//ETH RPC
	var err error
	//区块链合约初始化
	cfxclientRPC, err = sdk.NewClient("https://test.confluxrpc.com", sdk.ClientOption{
		KeystorePath: "keystore",
	})
	if err != nil {
		fmt.Println("failed to dial conflux node2 rpc", err)
		panic(err)
	}
}

//生成一个未签名的交易
func CreateUnsignedTx(from cfxaddress.Address, contract cfxaddress.Address, abi []byte, method string, args ...interface{}) (*types.UnsignedTransaction, error) {
	CFXcontract, err := cfxclientRPC.GetContract(abi, &contract) //更具合约地址得到 合约
	if err != nil {
		return nil, err
	}
	var OPT types.ContractMethodSendOption
	OPT.From = &from
	// var cid hexutil.Uint = 1
	// OPT.ChainID = &cid
	OPT.GasPrice = (*hexutil.Big)(big.NewInt(1000000000)) //1G drips
	UnsignedTx, err := GetABIUnsignData(CFXcontract, &OPT, method, args...)
	if err != nil {
		return nil, err
	} else {
		return UnsignedTx, nil
	}
}
func GetABIUnsignData(CFXcontract *sdk.Contract, option *types.ContractMethodSendOption, method string, args ...interface{}) (*types.UnsignedTransaction, error) {
	tx := new(types.UnsignedTransaction)
	data, err := CFXcontract.GetData(method, args...)
	if err != nil {
		return tx, errors.Wrap(err, "failed to encode call data")
	}

	if option != nil {
		tx.UnsignedTransactionBase = types.UnsignedTransactionBase(*option)
	}
	tx.To = CFXcontract.Address
	tx.Data = data
	err = CFXcontract.Client.ApplyUnsignedTransactionDefault(tx)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

//post 服务
func SignTxDataPost(thurl string, actionName string, account string, secret string, phone string, OpenID string, unsigntxjson []byte, from string, paymentpass string, chaintype string) ([]byte, error) {
	now := time.Now().Unix() //获取当前时间
	//post请求提交json数据
	messages := SignRequist_Message{account, secret, phone, OpenID, now, acc.SHA256_strReturnString(account + OpenID + fmt.Sprint(time.Now().UnixMilli())),
		unsigntxjson, from, paymentpass, chaintype}
	ba, err := json.Marshal(messages)
	if err != nil {
		return nil, err
	}
	resp, err := HalfPrvDataPostclient.Post(thurl+"/"+actionName+"", "application/json", bytes.NewBuffer([]byte(ba)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

//给与信任方的快速注册Jugugu
func FastRegJugugu(thurl string, actionName string, myappid string, phone string) ([]byte, error) {
	return nil, nil
}

//
