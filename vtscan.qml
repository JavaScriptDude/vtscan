import QtQuick 2.2
import QtQuick.Window 2.2
import QtQuick.Layouts 1.6
import QtQuick.Controls 1.4

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

            Label {
                id: lblFile
                text: "File: "
                font.pixelSize: 16
                color: "gray"
                Layout.alignment: Qt.AlignRight
            }
            Label {
                id: txtFile
                objectName: "txtFile"
                text: "TBD"
                font.pixelSize: 14
                color: "black"
            }


            Label {
                id: lblPath
                text: "Path: "
                font.pixelSize: 16
                color: "gray"
                Layout.alignment: Qt.AlignRight
            }
            Label {
                id: txtPath
                objectName: "txtPath"
                text: "<path>"
                font.pixelSize: 14
                color: "black"
            }


            Label {
                id: lblMd5
                text: "md5: "
                font.pixelSize: 16
                color: "gray"
                Layout.alignment: Qt.AlignRight
            }
            Label {
                id: txtMd5
                objectName: "txtMd5"
                text: "<MD5>"
                font.pixelSize: 14
                color: "black"
            }


            Label {
                id: lblSha1
                text: "sha1: "
                font.pixelSize: 16
                color: "gray"
                Layout.alignment: Qt.AlignRight
            }
            Label {
                id: txtSha1
                objectName: "txtSha1"
                text: "<Sha1>"
                font.pixelSize: 14
                color: "black"
            }


            Label {
                id: lblSha256
                text: "sha256: "
                font.pixelSize: 16
                color: "gray"
                Layout.alignment: Qt.AlignRight
            }
            Label {
                id: txtSha256
                objectName: "txtSha256"
                text: "<Sha256>"
                font.pixelSize: 14
                color: "black"
            }


            Label {
                id: lblLink
                text: "Permalink: "
                font.pixelSize: 16
                color: "gray"
                Layout.alignment: Qt.AlignRight
            }
            Label {
                id: txtLink
                objectName: "txtLink"
                text: "<Permalink>"
                onLinkActivated: Qt.openUrlExternally(link)
                font.pixelSize: 14
                color: "black"
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


        Label {
            id: lblRes
            text: "Results: "
            font.pixelSize: 16
            color: "gray"
            anchors.top: qrcode.bottom;
        }
        Label {
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