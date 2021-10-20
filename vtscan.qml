import QtQuick 2.2
import QtQuick.Window 2.2
import QtQuick.Layouts 1.6

Window {
    visible: true
    width: 800
    height: 500
    title: "Virus Total Scanner"
    Rectangle {
        id: recText
        anchors.margins: 10
        color: "transparent"
        anchors.fill: parent

        GridLayout {
            id: gridText
            columns:2

            Text {
                id: lblFile
                text: "File: "
                font.pixelSize: 16
                color: "gray"
                Layout.alignment: Qt.AlignRight
            }
            Text {
                id: txtFile
                objectName: "txtFile"
                text: "TBD"
                font.pixelSize: 14
                color: "black"
            }


            Text {
                id: lblPath
                text: "Path: "
                font.pixelSize: 16
                color: "gray"
                Layout.alignment: Qt.AlignRight
            }
            Text {
                id: txtPath
                objectName: "txtPath"
                text: "<path>"
                font.pixelSize: 14
                color: "black"
            }


            Text {
                id: lblMd5
                text: "md5: "
                font.pixelSize: 16
                color: "gray"
                Layout.alignment: Qt.AlignRight
            }
            Text {
                id: txtMd5
                objectName: "txtMd5"
                text: "<MD5>"
                font.pixelSize: 14
                color: "black"
            }


            Text {
                id: lblSha1
                text: "sha1: "
                font.pixelSize: 16
                color: "gray"
                Layout.alignment: Qt.AlignRight
            }
            Text {
                id: txtSha1
                objectName: "txtSha1"
                text: "<Sha1>"
                font.pixelSize: 14
                color: "black"
            }


            Text {
                id: lblSha256
                text: "sha256: "
                font.pixelSize: 16
                color: "gray"
                Layout.alignment: Qt.AlignRight
            }
            Text {
                id: txtSha256
                objectName: "txtSha256"
                text: "<Sha256>"
                font.pixelSize: 14
                color: "black"
            }


            Text {
                id: lblLink
                text: "Permalink: "
                font.pixelSize: 16
                color: "gray"
                Layout.alignment: Qt.AlignRight
            }
            Text {
                id: txtLink
                objectName: "txtLink"
                text: "<Permalink>"
                font.pixelSize: 14
                color: "black"
                onLinkActivated: Qt.openUrlExternally(link)
                MouseArea {
                    id: mouseArea
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                }
            }

        }


        Image {
            id: qrcode
            objectName: "qrcode"
            source: ""
            height: 300
            width: 300
            anchors.top: gridText.bottom
        }


        Text {
            id: lblRes
            text: "Results: "
            font.pixelSize: 16
            color: "gray"
            anchors.top: qrcode.bottom;
        }
        Text {
            id: txtRes
            objectName: "txtRes"
            text: "<Results>"
            font.pixelSize: 14
            color: "black"
            anchors.left: lblRes.right;
            anchors.bottom: lblRes.bottom;
        }

    }
}