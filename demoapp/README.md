Oracle Forms sample apps for testing
====================================

I recommend the [tutoforms10g](http://sheikyerbouti.developpez.com/tutoforms10g/tutoforms10g.htm) application for testing.

Additionally in this directory there's some code I created, because I was unable to recompile the above sample.

For these demos I added the following configuration section to formsweb.cfg:

    [hacktivity]
    envFile=tutforms10g.env
    archive_jini=frmall_jinit.jar,myIcons.jar,FormsGraph.jar
    archive=frmall.jar,myIcons.jar,FormsGraph.jar
    pageTitle=Oracle Forms 10g tutorial
    WebUtilArchive=frmwebutil.jar,jacob.jar
    WebUtilLogging=off
    WebUtilLoggingDetail=normal
    WebUtilErrorMode=Alert
    WebUtilDispatchMonitorInterval=5
    WebUtilTrustInternal=true
    WebUtilMaxTransferSize=16384
    baseHTML=base.htm
    baseHTMLjinitiator=basejpi.htm
    baseHTMLjpi=basejpi.htm
    form=hacktivity.fmx
    separateFrame=True
    lookandfeel=Oracle
    imagebase=codebase
    width=900
    height=700
    splashScreen=no
    background=no
    lookAndFeel=Oracle
    colorScheme=blaf
    logo=no
    IE=native
    jpi_download_page=http://java.sun.com/products/archive/j2se/1.4.2_06/index.html
    jpi_classid=clsid:CAFEEFAC-0014-0002-0006-ABCDEFFEDCBA
    jpi_codebase=http://java.sun.com/products/plugin/autodl/jinstall-1_4_2-windows-i586.cab#Version=1,4,2,06
    jpi_mimetype=application/x-java-applet;jpi-version=1.8.0_25
    #don't forget to put your own database connexion
    userid=SYSTEM/oracle@127.0.0.1/XE

The config section references the unmodified .env file of tutoforms10g:

    #oracle home  adapt this value to your own setting
    ORACLE_HOME=C:\DevSuiteHome_1

    FORMS_PATH=%ORACLE_HOME%\forms\tutoforms
    ORACLE_PATH=%ORACLE_HOME%\forms\tutoforms
    FORMS_TRACE_PATH=%ORACLE_HOME%\forms\tutoforms
    CLASSPATH=C:\DevSuiteHome_1\forms\java\frmwebutil.jar;%ORACLE_HOME%\jlib\debugger.jar;%ORACLE_HOME%\forms\tutoforms\FormsGraph.jar;%ORACLE_HOME%\forms\tutoforms\myIcons.jar;

    # webutil config file path
    WEBUTIL_CONFIG=C:\DevSuiteHome_1\forms\server\webutil.cfg

The new sample app can be accessed via the `/forms/frmservlet?config=hacktivity` URL path.
