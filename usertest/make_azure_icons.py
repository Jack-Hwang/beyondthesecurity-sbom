# -*- coding: utf-8 -*-
"""Generate Azure-brand-style flat icon PNGs (128px) for the operations deck.

The official Azure architecture icon set could not be downloaded in this offline session, so these are
hand-drawn simplifications in the official brand geometry (flat, white glyph on the product's brand color,
rounded-rect tile) - they read as Azure product tiles but are NOT the official artwork. Each tile labels itself
in the deck, so a viewer is never asked to identify a product by the icon alone.
"""
from PIL import Image, ImageDraw

S = 128


def tile(bg, name):
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([6, 6, S - 6, S - 6], radius=22, fill=bg)
    return img, d


def save(img, path):
    img.save(path, "PNG")


def icon_container(path):
    img, d = tile("#1B93B3", "container")          # Container Apps teal
    for i, y in enumerate((28, 52, 76)):
        d.rounded_rectangle([28, y, 100, y + 16], radius=6, fill=(255, 255, 255, 235))
    d.rectangle([28, 100, 100, 104], fill=(255, 255, 255, 180))
    save(img, path)


def icon_registry(path):
    img, d = tile("#2D7FD1", "registry")           # ACR blue
    d.polygon([(64, 24), (100, 44), (100, 84), (64, 104), (28, 84), (28, 44)], fill=(255, 255, 255, 235))
    d.polygon([(64, 46), (84, 56), (84, 74), (64, 84), (44, 74), (44, 56)], fill=bg_overlay())
    save(img, path)


def bg_overlay():
    return (45, 127, 209, 255)


def icon_storage(path):
    img, d = tile("#2178BD", "storage")            # Storage blue
    for y in (30, 56, 82):
        d.ellipse([28, y, 100, y + 18], outline=(255, 255, 255, 235), width=6)
    d.rectangle([28, 39, 100, 91], fill=(33, 120, 189, 255))
    for y in (30, 56, 82):
        d.ellipse([28, y, 100, y + 18], outline=(255, 255, 255, 235), width=6)
    save(img, path)


def icon_logs(path):
    img, d = tile("#0F7EA8", "logs")               # Log Analytics blue
    d.line([(30, 92), (52, 60), (72, 74), (98, 34)], fill=(255, 255, 255, 235), width=9, joint="curve")
    d.ellipse([92, 28, 104, 40], fill=(255, 255, 255, 235))
    save(img, path)


def icon_identity(path):
    img, d = tile("#C7A100", "identity")           # Entra gold
    d.ellipse([40, 26, 88, 62], fill=(255, 255, 255, 235))
    d.pieslice([32, 60, 96, 116], 180, 360, fill=(255, 255, 255, 235))
    save(img, path)


def icon_ai(path):
    img, d = tile("#3D5DA8", "ai")                 # Azure OpenAI indigo
    d.ellipse([30, 30, 98, 98], outline=(255, 255, 255, 235), width=8)
    d.ellipse([48, 48, 80, 80], fill=(255, 255, 255, 235))
    d.ellipse([58, 58, 70, 70], fill=(61, 93, 168, 255))
    save(img, path)


def icon_network(path):
    img, d = tile("#39A845", "network")            # VNet green
    for x in (40, 64, 88):
        d.ellipse([x - 10, 24, x + 10, 44], fill=(255, 255, 255, 235))
        d.ellipse([x - 10, 84, x + 10, 104], fill=(255, 255, 255, 235))
        d.line([(x, 44), (x, 84)], fill=(255, 255, 255, 200), width=5)
    d.line([(40, 34), (88, 34)], fill=(255, 255, 255, 200), width=5)
    d.line([(40, 94), (88, 94)], fill=(255, 255, 255, 200), width=5)
    save(img, path)


def icon_monitor(path):
    img, d = tile("#096B8F", "monitor")            # Monitor blue
    d.rounded_rectangle([26, 30, 102, 86], radius=8, outline=(255, 255, 255, 235), width=7)
    d.line([(48, 96), (80, 96)], fill=(255, 255, 255, 235), width=7)
    d.line([(64, 86), (64, 96)], fill=(255, 255, 255, 235), width=7)
    d.line([(38, 66), (54, 48), (70, 60), (90, 42)], fill=(255, 255, 255, 235), width=6, joint="curve")
    save(img, path)


def icon_shield(path):
    img, d = tile("#8A2DA8", "shield")             # security purple
    d.polygon([(64, 22), (100, 36), (100, 70), (64, 106), (28, 70), (28, 36)], fill=(255, 255, 255, 235))
    d.line([(46, 64), (60, 78), (84, 48)], fill=(138, 45, 168, 255), width=10, joint="curve")
    save(img, path)


def icon_sbom(path):
    img, d = tile("#5C2D91", "sbom")               # product purple
    for i, x in enumerate((30, 50, 70, 90)):
        h = 30 + (i % 2) * 16
        d.rectangle([x - 8, 98 - h, x + 8, 98], fill=(255, 255, 255, 235))
    d.rectangle([26, 24, 102, 32], fill=(255, 255, 255, 180))
    save(img, path)


def icon_chat(path):
    img, d = tile("#B03A5B", "chat")               # dock rose
    d.rounded_rectangle([24, 34, 104, 84], radius=14, fill=(255, 255, 255, 235))
    d.polygon([(44, 84), (44, 104), (64, 84)], fill=(255, 255, 255, 235))
    for y in (50, 64):
        d.line([(38, y), (90, y)], fill=(176, 58, 91, 255), width=6)
    save(img, path)


if __name__ == "__main__":
    import os
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "azure_icons")
    os.makedirs(out, exist_ok=True)
    icon_container(os.path.join(out, "container_apps.png"))
    icon_registry(os.path.join(out, "acr.png"))
    icon_storage(os.path.join(out, "storage.png"))
    icon_logs(os.path.join(out, "log_analytics.png"))
    icon_identity(os.path.join(out, "identity.png"))
    icon_ai(os.path.join(out, "openai.png"))
    icon_network(os.path.join(out, "vnet.png"))
    icon_monitor(os.path.join(out, "monitor.png"))
    icon_shield(os.path.join(out, "security.png"))
    icon_sbom(os.path.join(out, "sbom.png"))
    icon_chat(os.path.join(out, "chat.png"))
    print("icons written to", out)
