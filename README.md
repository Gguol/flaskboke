Flaskboke
====
该项目是按照Flask Web开发一书来完成的，也是个人的第一个flask项目。
----
### 利用Flask 搭建个人博客系统
#### 所用工具：Windows10、Pycharm
#### Python版本为`3.6.4`
##### 应用程序整体目录结构
|-----flaskboke 总目录 \<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;|------app/		存放flask程序<br>
                  |------templates/		模板文件 .html
                  |------static/			存放静态文件，如图片、JS源码文件和CSS
                  |------main/			main蓝本（在蓝本中定义的路由处于休眠状态直		  |   			到蓝本注册到程序上后。）
                          |------__init__.py      创建蓝本（实例化一个Blueprint类对象）
                          |------errors.py        蓝本中的错误处理程序（如404,500）
                          |------forms.py		  表单对象（如NameForm、PostForm等）
                          |------views.py		  程序路由，即视图函数（index等）
                  |------__init__.py       程序包的构造文件（程序工厂函数create_app（））
                  |------email.py			 集成在程序中的异步发送电子邮件功能
                  |------models.py		 模型（即数据库表）如Role、User
          |------migrations/             数据库迁移仓库
          |------tests/					 测试程序文件
                  |------__init__.py
                  |------test*.py			 各种单元测试
          |------venv/					 包含python虚拟环境
          |------requirements.txt		 列出所有依赖包可在其他地方生成相同虚拟环境
          |------config.py				 存储配置
          |------manage.py				 用于启动程序以及其他的程序任务
