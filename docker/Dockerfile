FROM python:3.6.15
WORKDIR /oraforms
RUN git clone https://github.com/v-p-b/oracle_forms
RUN pip install mitmproxy==4.0.4
RUN pip install requests
WORKDIR /oraforms/oracle_forms
CMD ["mitmdump", "-s" ,"mitmproxy_oracleforms.py" ,"-p" ,"8081" ]

