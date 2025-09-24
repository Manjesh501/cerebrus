#!/usr/bin/env python3
"""
Create simple PNG icons for Cerberus Chrome Extension
"""
import os
from PIL import Image, ImageDraw, ImageFont

def create_icon(size, output_path):
    """Create a simple shield icon"""
    # Create image with transparent background
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Draw shield shape
    margin = size // 8
    width = size - 2 * margin
    height = size - 2 * margin
    
    # Shield coordinates
    points = [
        (margin + width//2, margin),  # top center
        (margin + width, margin + height//3),  # top right
        (margin + width, margin + 2*height//3),  # bottom right
        (margin + width//2, margin + height),  # bottom center
        (margin, margin + 2*height//3),  # bottom left
        (margin, margin + height//3),  # top left
    ]
    
    # Draw shield with gradient effect (simplified)
    draw.polygon(points, fill=(102, 126, 234, 255), outline=(255, 255, 255, 255))
    
    # Add "C" text if size is large enough
    if size >= 32:
        try:
            font_size = size // 3
            font = ImageFont.truetype("arial.ttf", font_size)
        except:
            font = ImageFont.default()
        
        # Get text bbox for centering
        bbox = draw.textbbox((0, 0), "C", font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
        
        x = (size - text_width) // 2
        y = (size - text_height) // 2
        
        draw.text((x, y), "C", fill=(255, 255, 255, 255), font=font)
    
    # Save the image
    img.save(output_path, 'PNG')
    print(f"Created icon: {output_path}")

def main():
    # Create icons directory
    icons_dir = "icons"
    os.makedirs(icons_dir, exist_ok=True)
    
    # Create icons in different sizes
    sizes = [16, 32, 48, 128]
    
    for size in sizes:
        output_path = os.path.join(icons_dir, f"icon{size}.png")
        create_icon(size, output_path)
    
    print("All icons created successfully!")

if __name__ == "__main__":
    main()