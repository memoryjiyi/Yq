# -*- coding: utf-8 -*-
"""
HJ212-2017 协议报文解析工具
报文格式：## + 4位长度 + 数据体 + 4位校验码 + 回车换行
"""


class HJ212Parser:
    """污染物在线监测数据传输协议解析器"""

    # 协议固定参数
    HEAD = "##"
    TAIL = "\r\n"
    LEN_SIZE = 4
    CRC_SIZE = 4
    CRC_INIT = 0xFFFF
    CRC_POLY = 0xA001

    @staticmethod
    def _calc_checksum(text):
        """计算一段文本的 ANSI CRC16 值，返回整数"""
        reg = HJ212Parser.CRC_INIT
        for ch in text.encode("utf-8"):
            reg ^= ch
            for _ in range(8):
                if reg & 1:
                    reg = (reg >> 1) ^ HJ212Parser.CRC_POLY
                else:
                    reg >>= 1
        return reg & 0xFFFF

    @staticmethod
    def _checksum_hex(text):
        """返回4位大写十六进制校验码"""
        return "{:04X}".format(HJ212Parser._calc_checksum(text))

    def _body(self, msg):
        """从完整报文中切出数据体部分，失败返回None"""
        if not isinstance(msg, str):
            return None
        if not msg.startswith(self.HEAD) or not msg.endswith(self.TAIL):
            return None
        size_field = msg[len(self.HEAD):len(self.HEAD) + self.LEN_SIZE]
        if not size_field.isdigit():
            return None
        n = int(size_field)
        body_start = len(self.HEAD) + self.LEN_SIZE
        body = msg[body_start:body_start + n]
        if len(body) != n:
            return None
        return body

    def is_valid_message(self, message):
        """
        检查报文格式是否正确。
        逐项验证：包头、包尾、长度字段是否为数字、声明长度与实际是否吻合、校验码是否为合法十六进制。
        """
        if not isinstance(message, str):
            return False
        # 包头包尾
        if not message.startswith(self.HEAD) or not message.endswith(self.TAIL):
            return False
        # 最短长度判断
        minimum = len(self.HEAD) + self.LEN_SIZE + self.CRC_SIZE + len(self.TAIL)
        if len(message) < minimum:
            return False
        # 长度字段
        size_field = message[len(self.HEAD):len(self.HEAD) + self.LEN_SIZE]
        if not size_field.isdigit():
            return False
        body_len = int(size_field)
        # 总长度 = 包头 + 长度字段 + 数据体 + 校验码 + 包尾
        expected = len(self.HEAD) + self.LEN_SIZE + body_len + self.CRC_SIZE + len(self.TAIL)
        if len(message) != expected:
            return False
        # 校验码字段必须是4位十六进制
        crc_field = message[-len(self.TAIL) - self.CRC_SIZE:-len(self.TAIL)]
        if len(crc_field) != self.CRC_SIZE:
            return False
        try:
            int(crc_field, 16)
        except ValueError:
            return False
        return True

    def validate_crc(self, message):
        """
        实现ANSI CRC16算法，校验报文的CRC值。
        对数据体部分重新计算校验码，与报文中携带的校验码比对。
        """
        if not self.is_valid_message(message):
            return False
        body = self._body(message)
        if body is None:
            return False
        carried = message[-len(self.TAIL) - self.CRC_SIZE:-len(self.TAIL)]
        return self._checksum_hex(body).upper() == carried.upper()

    def parse_data_segment(self, message):
        """
        解析数据段，返回包含所有键值对的字典。
        普通字段用分号分隔；CP字段用&&包裹，内部可能含分号，需特殊处理。
        """
        result = {}
        body = self._body(message)
        if body is None:
            return result

        # 把 CP=&&...&& 整体替换成占位符，避免被分号拆断
        marker = "@@CP@@"
        raw_cp = None
        begin = body.find("CP=&&")
        if begin != -1:
            end = body.find("&&", begin + 5)
            if end != -1:
                end += 2
                raw_cp = body[begin:end]
                body = body[:begin] + "CP=" + marker + body[end:]

        for piece in body.split(";"):
            piece = piece.strip()
            if not piece or "=" not in piece:
                continue
            key, val = piece.split("=", 1)
            if key == "CP" and val == marker and raw_cp:
                result["CP"] = raw_cp[3:]  # 去掉 "CP="
            else:
                result[key] = val
        return result

    def extract_monitoring_data(self, message):
        """
        从CP字段中提取所有监测因子及其数值。
        CP数据区内：项目之间用分号隔开，同一项目的多个属性用逗号隔开。
        返回字典，键为完整的因子标识（如 a01-Rtd），值为对应数据。
        """
        fields = self.parse_data_segment(message)
        cp_raw = fields.get("CP", "")
        if not (cp_raw.startswith("&&") and cp_raw.endswith("&&")):
            return {}

        inner = cp_raw[2:-2]
        extracted = {}
        for group in inner.split(";"):
            if not group:
                continue
            for pair in group.split(","):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    extracted[k.strip()] = v.strip()
        return extracted

    def assemble(self, body):
        """辅助方法：根据数据体拼装完整报文，便于自测"""
        size = "{:04d}".format(len(body))
        code = self._checksum_hex(body)
        return self.HEAD + size + body + code + self.TAIL


# -------------------- 自测 --------------------
if __name__ == "__main__":
    parser = HJ212Parser()

    # 构造一条测试报文（污水监测场景）
    sample_body = (
        "QN=20261009203000000;ST=31;CN=2011;PW=888888;MN=WATER_STATION_01;"
        "Flag=001;CP=&&DataTime=20261009203000;"
        "w01018-Rtd=23.6,w01018-Flag=N;"
        "w01019-Rtd=6.8,w01019-Flag=N;"
        "w21003-Rtd=0.92,w21003-Min=0.80,w21003-Max=1.05,w21003-Avg=0.91,w21003-Flag=N&&"
    )
    packet = parser.assemble(sample_body)
    print("【生成的报文】")
    print(repr(packet))
    print()

    print("【1】格式合法性 :", parser.is_valid_message(packet))
    print("【2】CRC校验    :", parser.validate_crc(packet))
    print("【3】数据段解析  :")
    for k, v in parser.parse_data_segment(packet).items():
        show = v if len(v) <= 60 else v[:57] + "..."
        print("     {:<6} = {}".format(k, show))
    print("【4】监测因子提取:")
    for k, v in parser.extract_monitoring_data(packet).items():
        print("     {:<14} = {}".format(k, v))
