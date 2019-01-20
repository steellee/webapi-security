#  开放接口设计-解决方案
   * 安全设计（防窃取，防篡改，防泄漏）
   * 多版本管理支持

## 一. 简单验签加密组件
### 1. 介绍说明

     * BASE64 严格地说，属于编码格式，而非加密算法；双向加密（可解密）
        使用场景：任意序列的8位字节描述为一种不易被人直接识别的形式如：空格等，转化成任何国际语言都能识别的64个可见字符
     * MD5(Message Digest algorithm 5，信息摘要算法)，单向加密；
        使用场景：用来校验数据在传输过程中是否被修改
     * SHA(Secure Hash Algorithm，安全散列算法)，单向加密；
        使用场景：用来校验数据在传输过程中是否被修改
     * HMAC(Hash Message Authentication Code，散列消息鉴别码)单向加密；
        使用场景：用来校验数据在传输过程中是否被修改；多了一个密钥，增强了数据传输过程中的安全性
     
### 2. 实例流程
    
    参照实例：CodersTest

## 二. 对称加密组件
### 1. 介绍说明

    对称加密算法: 
        较传统的加密体制，通信双方在加/解密过程中使用他们共享的单一密钥，鉴于其算法简单和加密速度快的优点，目前仍然是主流的密码体制之一。
    最常用的对称密码算法是数据加密标准（DES）算法，但是由于DES密钥长度较短，已经不适合当今分布式开放网络对数据加密安全性的要求。
    最后，一种新的基于Rijndael算法对称高级数据加密标准AES取代了数据加密标准DES。
    
    ALGORITHM -->  算法/模式/补码方式; 如: AES -> 默认使用AES/ECB/PKCS5Padding
    1，算法: DES, DESede, AES,...RC4
      各自密钥长度不同
     * DES          key size must be equal to 56 
     * DESede(TripleDES) key size must be equal to 112 or 168 
     * AES          key size must be equal to 128, 192 or 256,but 192 and 256 bits may not be available 
     * Blowfish     key size must be multiple of 8, and can only range from 32 to 448 (inclusive) 
     * RC2          key size must be between 40 and 1024 bits 
     * RC4(ARCFOUR) key size must be between 40 and 1024 bits 
          
     2，加密模式: CBC、ECB、CTR、OCF、CFB
     /参照：https://blog.csdn.net/xiaowang627/article/details/56270206/
 
     // AES一般是16个字节为一块，然后对这一整块进行加密，如果输入的字符串不够16个字节，就需要补位
     3，补码方式:  NoPadding，PKCS5Padding，ISO10126Padding
     参照：http://blog.sina.com.cn/s/blog_679daa6b0100zmpp.html
     PKCS5Padding：填充的原则是，如果长度少于16个字节，需要补满16个字节，补(16-len)个(16-len)
     例如: 123这个节符串是3个字节，16-3= 13,补满后如：123+13个十进制的13，
     
### 2. 实例流程

    参照实例：AesCoderTest

## 三. AES加解密数据 + RSA验签
### 1. 介绍说明

    数据加密技术根据加密密钥类型可分私钥加密（对称加密）系统和公钥加密（非对称加密）系统。
    非对称加密:
        由于加/解密钥不同（公钥加密，私钥解密），密钥管理简单，也得到广泛应用。
        * DSA 基于整数有限域离散对数难题的，安全性与RSA相比差不多，只用于签名；
        * RSA 安全性依赖于大数分解，可用于签名,用于少量数据加密，1978年提出至今，普遍认为是目前最优秀的公钥方案之一

### 2. 处理流程
              
    参照实例：AesRsaCoderTest
    RAS通用处理：
    client处理：通过server私钥加密、client公钥解密
    server处理：通过client私钥签名、client公钥验证签名
    （本实例RSA只对aseKey加密，参数传递用AES加解密）
    
#### 客户端处理：
##### 2.1 生成encryptkey：

    服务器端(server)和客户端(client)分别生成自己的密钥对
    * server和client分别交换自己的公钥
    * client生成AES密钥(aesKey)—可随机、可固定，client自己保存
    * client使用sever的RSA公钥对aesKey进行加密， 得到encryptkey

##### 2.2 生成sign：

    * client使用自己的RSA私钥(privateKey)对请求明文数据(data json)进行数字签名，得到数字签名sign
    * 将sign加入到请求参数中，然后转换为json格式

##### 2.3 加密请求data

    * client使用aesKey对json数据进行加密得到密文(data)

##### 2.4 请求服务器

    * 分别将data和encryptkey作为参数传输给服务器端


#### 服务端处理

    服务器端进行请求响应时将上面流程反过来即可

## 四. 国密
### 1. 介绍说明

    国密算法是我国自主研发创新的一套数据加密处理系列算法。主要有SM1，SM2，SM3，SM4。密钥长度和分组长度均为128位。
    从SM1-SM4分别实现了对称、非对称、摘要等算法功能。 特别适合应用于嵌入式物联网等相关领域，完成身份认证和数据加解密等功能。
    当然，默认的前提条件是算法密钥必须保证安全性，因此要将国密算法嵌入到硬件加密芯片中结合使用。
    (https://blog.csdn.net/u013758702/article/details/80241317)
    1) 介绍：
    SM1 为对称加密。其加密强度与AES相当。该算法不公开，调用该算法时，需要通过加密芯片的接口进行调用。
    SM2为非对称加密，基于非对称加密算法强度最高级ECC，椭圆曲线密码编码学。该算法已公开。由于该算法基于ECC，故其签名速度与秘钥生成速度都快于RSA。ECC 256位（SM2采用的就是ECC 256位的一种）安全强度比RSA 2048位高，但运算速度快于RSA。
    SM3 消息摘要。可以用MD5作为对比理解。该算法已公开。校验结果为256位
    SM4 无线局域网标准的分组数据算法。对称加密，密钥长度和分组长度均为128位。 
    
    2）安全性：
    SM2算法：SM2椭圆曲线公钥密码算法是我国自主设计的公钥密码算法，包括SM2-1椭圆曲线数字签名算法，SM2-2椭圆曲线密钥交换协议，SM2-3椭圆曲线公钥加密算法，分别用于实现数字签名密钥协商和数据加密等功能。SM2算法与RSA算法不同的是，SM2算法是基于椭圆曲线上点群离散对数难题，相对于RSA算法，256位的SM2密码强度已经比2048位的RSA密码强度要高。
    SM3算法：SM3杂凑算法是我国自主设计的密码杂凑算法，适用于商用密码应用中的数字签名和验证消息认证码的生成与验证以及随机数的生成，可满足多种密码应用的安全需求。为了保证杂凑算法的安全性，其产生的杂凑值的长度不应太短，例如MD5输出128比特杂凑值，输出长度太短，影响其安全性。SHA-1算法的输出长度为160比特，SM3算法的输出长度为256比特，因此SM3算法的安全性要高于MD5算法和SHA-1算法。
    SM4算法：SM4分组密码算法是我国自主设计的分组对称密码算法，用于实现数据的加密/解密运算，以保证数据和信息的机密性。要保证一个对称密码算法的安全性的基本条件是其具备足够的密钥长度，SM4算法与AES算法具有相同的密钥长度分组长度128比特，因此在安全性上高于3DES算法。
    
    SM1、SM4对消息进行加解密时，若消息长度过长，需要进行分组，要消息长度不足，则要进行填充。

### 2. 实例流程

    参照实例：SM2UtilTest， SM3UtilTest
    
    在1.59及之后的版本已经基本实现了国密算法（SM2、SM3、SM4），本项目是基于BC库做的一些功能的简单封装
    BC库（ https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15on）
    BC库官网github：https://github.com/bcgit/bc-java
    依赖组件：
    <!--加密算法的Java实现-->
    <dependency>
        <groupId>org.bouncycastle</groupId>
        <artifactId>bcprov-jdk15on</artifactId>
        <version>1.60</version>
    </dependency>
    <!--用于CMS、PKCS、EAC、TSP、CMP、CRMF、OCSP和证书生成的Java api-->
    <dependency>
        <groupId>org.bouncycastle</groupId>
        <artifactId>bcpkix-jdk15on</artifactId>
        <version>1.60</version>
    </dependency>
    
    
    
## 五. 多版本管理支持
### 1. 介绍说明   

    针对前端，比如android,ios，一旦上线的接口可能就永远都难以变动（除非你强制客户端用户升级），
    这时候，针对后端所有接口进行版本管理就显得很重要了，比如某个添加用户的接口，
    由于业务发展很大，接口的字段属性变化很大，只能重新定义一个新的接口，
    由 /v1/user/add 变成了 /v2/user/add，这样我们就要维护两套接口的逻辑，映射到代码里，就是要维护两个不同的业务方法。
    因此我们需要通过扩展开发来方便我们在代码层级管理各不同的版本接口。
        
### 2. 实例流程 

    参照：MultiApiController
    http://localhost:8080/v1/hello/, 调用版本1 的管理
    http://localhost:8080/v2/hello/, 调用版本2 的管理
    http://localhost:8080/v5/hello   调用版本5 的管理
    http://localhost:8080/v4/hello/来访问接口，
    则要自动适配到 http://localhost:8080/v2/hello/，因为 v2是比v4低的版本中最新的版本
    