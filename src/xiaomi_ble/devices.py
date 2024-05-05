import dataclasses


@dataclasses.dataclass
class DeviceEntry:
    name: str
    model: str
    manufacturer: str = "Xiaomi"


DEVICE_TYPES: dict[int, DeviceEntry] = {
    0x0C3C: DeviceEntry(
        name="Alarm Clock",
        model="CGC1",
    ),
    0x0576: DeviceEntry(
        name="3-in-1 Alarm Clock",
        model="CGD1",
    ),
    0x066F: DeviceEntry(
        name="Temperature/Humidity Sensor",
        model="CGDK2",
    ),
    0x0347: DeviceEntry(
        name="Temperature/Humidity Sensor",
        model="CGG1",
    ),
    0x0B48: DeviceEntry(
        name="Temperature/Humidity Sensor",
        model="CGG1-ENCRYPTED",
    ),
    0x03D6: DeviceEntry(
        name="Door/Window Sensor",
        model="CGH1",
    ),
    0x0A83: DeviceEntry(
        name="Motion/Light Sensor",
        model="CGPR1",
    ),
    0x03BC: DeviceEntry(
        name="Grow Care Garden",
        model="GCLS002",
    ),
    0x0098: DeviceEntry(
        name="Plant Sensor",
        model="HHCCJCY01",
    ),
    0x015D: DeviceEntry(
        name="Smart Flower Pot",
        model="HHCCPOT002",
    ),
    0x02DF: DeviceEntry(
        name="Formaldehyde Sensor",
        model="JQJCY01YM",
    ),
    0x0997: DeviceEntry(
        name="Smoke Detector",
        model="JTYJGD03MI",
    ),
    0x1568: DeviceEntry(
        name="Switch (single button)",
        model="K9B-1BTN",
    ),
    0x1569: DeviceEntry(
        name="Switch (double button)",
        model="K9B-2BTN",
    ),
    0x0DFD: DeviceEntry(
        name="Switch (triple button)",
        model="K9B-3BTN",
    ),
    0x1C10: DeviceEntry(
        name="Switch (single button)",
        model="K9BB-1BTN",
    ),
    0x1889: DeviceEntry(
        name="Door/Window Sensor",
        model="MS1BB(MI)",
    ),
    0x2AEB: DeviceEntry(
        name="Motion Sensor",
        model="HS1BB(MI)",
    ),
    0x3F0F: DeviceEntry(name="Flood and Rain Sensor", model="RS1BB(MI)"),
    0x01AA: DeviceEntry(
        name="Temperature/Humidity Sensor",
        model="LYWSDCGQ",
    ),
    0x045B: DeviceEntry(
        name="Temperature/Humidity Sensor",
        model="LYWSD02",
    ),
    0x16E4: DeviceEntry(
        name="Temperature/Humidity Sensor",
        model="LYWSD02MMC",
    ),
    0x2542: DeviceEntry(
        name="Temperature/Humidity Sensor",
        model="LYWSD02MMC",
    ),
    0x055B: DeviceEntry(
        name="Temperature/Humidity Sensor",
        model="LYWSD03MMC",
    ),
    0x2832: DeviceEntry(
        name="Temperature/Humidity Sensor",
        model="MJWSD05MMC",
    ),
    0x098B: DeviceEntry(
        name="Door/Window Sensor",
        model="MCCGQ02HL",
    ),
    0x06D3: DeviceEntry(
        name="Alarm Clock",
        model="MHO-C303",
    ),
    0x0387: DeviceEntry(
        name="Temperature/Humidity Sensor",
        model="MHO-C401",
    ),
    0x07F6: DeviceEntry(
        name="Nightlight",
        model="MJYD02YL",
    ),
    0x04E9: DeviceEntry(
        name="Door Lock",
        model="MJZNMSQ01YD",
    ),
    0x00DB: DeviceEntry(
        name="Baby Thermometer",
        model="MMC-T201-1",
    ),
    0x0391: DeviceEntry(
        name="Body Thermometer",
        model="MMC-W505",
    ),
    0x03DD: DeviceEntry(
        name="Nightlight",
        model="MUE4094RT",
    ),
    0x0489: DeviceEntry(
        name="Smart Toothbrush",
        model="M1S-T500",
    ),
    0x0806: DeviceEntry(
        name="Smart Toothbrush",
        model="T700",
    ),
    0x1790: DeviceEntry(
        name="Smart Toothbrush",
        model="T700",
    ),
    0x0A8D: DeviceEntry(
        name="Motion Sensor",
        model="RTCGQ02LM",
    ),
    0x3531: DeviceEntry(
        name="Motion Sensor",
        model="XMPIRO2SXS",
    ),
    0x0863: DeviceEntry(
        name="Flood Detector",
        model="SJWS01LM",
    ),
    0x045C: DeviceEntry(
        name="Smart Kettle",
        model="V-SK152",
    ),
    0x040A: DeviceEntry(
        name="Mosquito Repellent",
        model="WX08ZM",
    ),
    0x04E1: DeviceEntry(
        name="Magic Cube",
        model="XMMF01JQD",
    ),
    0x1203: DeviceEntry(
        name="Thermometer",
        model="XMWSDJ04MMC",
    ),
    0x1949: DeviceEntry(
        name="Switch (double button)",
        model="XMWXKG01YL",
    ),
    0x2387: DeviceEntry(
        name="Button",
        model="XMWXKG01LM",
    ),
    0x098C: DeviceEntry(
        name="Door Lock",
        model="XMZNMST02YD",
    ),
    0x0784: DeviceEntry(
        name="Door Lock",
        model="XMZNMS04LM",
    ),
    0x0E39: DeviceEntry(
        name="Door Lock",
        model="XMZNMS08LM",
    ),
    0x07BF: DeviceEntry(
        name="Wireless Switch",
        model="YLAI003",
    ),
    0x38BB: DeviceEntry(
        name="Wireless Switch",
        model="PTX_YK1_QMIMB",
    ),
    0x0153: DeviceEntry(
        name="Remote Control",
        model="YLYK01YL",
    ),
    0x068E: DeviceEntry(
        name="Fan Remote Control",
        model="YLYK01YL-FANCL",
    ),
    0x04E6: DeviceEntry(
        name="Ventilator Fan Remote Control",
        model="YLYK01YL-VENFAN",
    ),
    0x03BF: DeviceEntry(
        name="Bathroom Heater Remote",
        model="YLYB01YL-BHFRC",
    ),
    0x03B6: DeviceEntry(
        name="Dimmer Switch",
        model="YLKG07YL/YLKG08YL",
    ),
    0x0083: DeviceEntry(
        name="Smart Kettle",
        model="YM-K1501",
    ),
    0x0113: DeviceEntry(
        name="Smart Kettle",
        model="YM-K1501EU",
    ),
    0x069E: DeviceEntry(
        name="Door Lock",
        model="ZNMS16LM",
    ),
    0x069F: DeviceEntry(
        name="Door Lock",
        model="ZNMS17LM",
    ),
    0x0380: DeviceEntry(
        name="Door Lock",
        model="DSL-C08",
    ),
    0x11C2: DeviceEntry(
        name="Door Lock",
        model="Lockin-SV40",
    ),
    0x0DE7: DeviceEntry(
        name="Odor Eliminator",
        model="SU001-T",
    ),
}


SLEEPY_DEVICE_MODELS = {"CGH1", "JTYJGD03MI", "MCCGQ02HL", "RTCGQ02LM", "MMC-W505"}
