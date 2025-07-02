from PIL import Image, ImageDraw, ImageFont

# Create a blank image with blue background
size = (256, 256)
img = Image.new('RGBA', size, (30, 144, 255, 255))  # DodgerBlue

draw = ImageDraw.Draw(img)

# Try to use a cursive font, fallback to default if not available
try:
    font = ImageFont.truetype("BrushScriptStd.otf", 200)
except:
    try:
        font = ImageFont.truetype("arial.ttf", 200)
    except:
        font = ImageFont.load_default()

# Use textbbox for accurate text size (Pillow >=8.0)
try:
    bbox = draw.textbbox((0, 0), 'i', font=font)
    w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
except AttributeError:
    w, h = font.getsize('i')

draw.text(((size[0]-w)//2, (size[1]-h)//2-10), 'i', font=font, fill=(255,255,255,255))

# Save as PNG and ICO
img.save('icon.png')
img.save('icon.ico', format='ICO')
print('icon.ico created.')
