# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab
from javax.swing import JPanel, JTextField, JButton, JTable, JScrollPane, GroupLayout, JLabel
from javax.swing.table import DefaultTableModel
from java.awt import Font
import uuid
from javax.swing.table import DefaultTableCellRenderer
from datetime import datetime
from java.awt import Dimension
from java.awt.event import ActionListener

class BurpExtender(IBurpExtender, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("UUID Decoder")

        self.mainPanel = JPanel()

        # Create layout for main panel
        layout = GroupLayout(self.mainPanel)
        self.mainPanel.setLayout(layout)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)

        # Create components
        self.inputField = JTextField(36)  # Adjusted size
        self.inputField.setPreferredSize(Dimension(300, 25))
        self.decodeButton = JButton("Decode")
        self.decodeButton.addActionListener(DecodeButtonListener(self))

        # Table setup
        column_names = ["Attribute", "Value"]
        self.tableModel = DefaultTableModel([], column_names)
        self.resultTable = JTable(self.tableModel)
        self.resultTable.setAutoCreateRowSorter(True)
        bold_renderer = DefaultTableCellRenderer()
        bold_renderer.setFont(Font("Tahoma", Font.BOLD, 12))
        self.resultTable.getColumnModel().getColumn(0).setCellRenderer(bold_renderer)
        scrollPane = JScrollPane(self.resultTable)
        
        # Organize layout
        layout.setHorizontalGroup(
            layout.createSequentialGroup()
            .addGap(50)  # Space from left side
            .addGroup(
                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addGroup(
                    layout.createSequentialGroup()
                    .addComponent(self.inputField)
                    .addComponent(self.decodeButton)
                )
                .addComponent(scrollPane)
            )
            .addGap(50)  # Space from right side
        )

        layout.setVerticalGroup(
            layout.createSequentialGroup()
            .addGap(50)  # Space from top
            .addGroup(
                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                .addComponent(self.inputField)
                .addComponent(self.decodeButton)
            )
            .addGap(20)  # Space between input and table
            .addComponent(scrollPane)
            .addGap(50)  # Space from bottom
        )

        # Add main panel to Burp's UI
        self._callbacks.customizeUiComponent(self.mainPanel)
        self._callbacks.addSuiteTab(self)

    def decodeUUID(self, event):
        uuid_str = self.inputField.getText()
        decoded = self.decode(uuid_str)
        self.tableModel.setRowCount(0)  # Clear table
        for k, v in decoded.items():
            self.tableModel.addRow([k, v])

    def decode(self, uuid_str):
        try:
            u = uuid.UUID(uuid_str)

            # Get version and variant
            version = u.version
            variant = "DCE 1.1, ISO/IEC 11578:1996" if u.variant == uuid.RFC_4122 else str(u.variant)

            # Convert to integer
            int_value = u.int

            # For version 1 of UUID (timestamp-based)
            if version == 1:
                timestamp = (u.time - 0x01b21dd213814000) / 1e7
                timestamp_utc = datetime.utcfromtimestamp(timestamp)
                microsecond_part = (u.time % 1e7) / 10
                microsecond_str = "{:06.1f}".format(microsecond_part)
                time_str = timestamp_utc.strftime('%Y-%m-%d %H:%M:%S.') + microsecond_str[:-1] + "7 UTC"
                clock_seq = "{} (usually random)".format(u.clock_seq)
                node = ':'.join(['{:02x}'.format((u.node >> elements) & 0xff) for elements in range(0, 8*6, 8)][::-1])
            else:
                time_str = "N/A"
                clock_seq = "N/A"
                node = "N/A"

            return {
                "Standard String Format": str(u),
                "Single Integer Value": int_value,
                "Version": "{} (time and node based)".format(version) if version == 1 else version,
                "Variant": variant,
                "Contents - Time": time_str,
                "Contents - Clock": clock_seq,
                "Contents - Node": node
            }
        except Exception as e:
            return {"Error": "Invalid UUID."}

    # ITab implementations
    def getTabCaption(self):
        return "UUID Decoder"
    
    def getUiComponent(self):
        return self.mainPanel

class DecodeButtonListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, e):
        self.extender.decodeUUID(e)
