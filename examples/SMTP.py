#!/usr/bin/env python

from boofuzz import *


def main():
    session = Session(
        target=Target(
            connection=SocketConnection("127.0.0.1", 25, proto='tcp')
        ),
    )

    s_initialize(name="Request")
    with s_block("Request-Line"):
        s_group("Method", ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE'])
        s_delim(" ", name='space-1')
        s_string("/index.html", name='Request-URI')
        s_delim(" ", name='space-2')
        s_string('HTTP/1.1', name='HTTP-Version')
        s_static("\r\n", name="Request-Line-CRLF")
    s_static("\r\n", "Request-CRLF")

    s_initialize(name="HELO")
    s_static("HELO")
    s_delim(" ")
    # host name
    s_string("XPCLIENT")
    s_static("\r\n")

    s_initialize(name="MAIL")
    s_static("MAIL")
    s_delim(" ")
    s_string("FROM")
    s_delim(":")
    s_delim(" ")
    s_string("<ermaomail@qq.com>")
    s_static("\r\n")

    s_initialize(name="RCPT")
    s_static("RCPT")
    s_delim(" ")
    s_string("TO")
    s_delim(":")
    s_delim(" ")
    s_string("<ermaomail@qq.com>")
    s_static("\r\n")

    s_initialize(name="DATA")
    s_static("DATA")
    s_static("\r\n")

    s_initialize(name="DATAFRAGMENT")
    s_string('''Message-ID: <000d01c62923$ab372570$0101a8c0@XPCLIENT>
From: "TEST-Imap" <ermaomail@qq.com>
To: <ermaomail@qq.com>
Subject: Test#2
Date: Sat, 4 Feb 2006 00:40:54 -0000
MIME-Version: 1.0
Content-Type: multipart/alternative;
	boundary="----=_NextPart_000_000A_01C62923.A7B94950"
X-Priority: 3
X-MSMail-Priority: Normal
X-Mailer: Microsoft Outlook Express 6.00.2900.2180
X-MimeOLE: Produced By Microsoft MimeOLE V6.00.2900.2180

This is a multi-part message in MIME format.

------=_NextPart_000_000A_01C62923.A7B94950
Content-Type: text/plain;
	charset="koi8-r"
Content-Transfer-Encoding: quoted-printable

Test #2
------=_NextPart_000_000A_01C62923.A7B94950
Content-Type: text/html;
    charset="koi8-r"
Content-Transfer-Encoding: quoted-printable

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<HTML><HEAD>
<META http-equiv=3DContent-Type content=3D"text/html; charset=3Dkoi8-r">
<META content=3D"MSHTML 6.00.2900.2523" name=3DGENERATOR>
<STYLE></STYLE>
</HEAD>
<BODY bgColor=3D#ffffff>
<DIV><FONT face=3DArial size=3D2>Test #2</FONT></DIV></BODY></HTML>

------=_NextPart_000_000A_01C62923.A7B94950--
''')
    s_static("\r\n.\r\n")

    s_initialize(name="QUIT")
    s_static("QUIT")
    s_static("\r\n")

    session.connect(s_get("HELO"))
    session.connect(s_get("HELO"), s_get("MAIL"))
    session.connect(s_get("MAIL"), s_get("RCPT"))
    session.connect(s_get("RCPT"), s_get("DATA"))
    session.connect(s_get("DATA"), s_get("DATAFRAGMENT"))
    session.connect(s_get("DATAFRAGMENT"), s_get("QUIT"))

    session.fuzz()


if __name__ == "__main__":
    main()
