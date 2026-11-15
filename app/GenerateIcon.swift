import AppKit

let output = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "/tmp/netguard-icon-1024.png"
let image = NSImage(size: NSSize(width: 1024, height: 1024))
image.lockFocus()

let background = NSBezierPath(roundedRect: NSRect(x: 62, y: 62, width: 900, height: 900), xRadius: 205, yRadius: 205)
let gradient = NSGradient(colors: [
    NSColor(calibratedRed: 0.12, green: 0.35, blue: 0.92, alpha: 1),
    NSColor(calibratedRed: 0.05, green: 0.70, blue: 0.72, alpha: 1)
])!
gradient.draw(in: background, angle: -42)

let shield = NSBezierPath()
shield.move(to: NSPoint(x: 512, y: 850))
shield.line(to: NSPoint(x: 764, y: 756))
shield.line(to: NSPoint(x: 736, y: 500))
shield.curve(to: NSPoint(x: 512, y: 160), controlPoint1: NSPoint(x: 724, y: 338), controlPoint2: NSPoint(x: 640, y: 230))
shield.curve(to: NSPoint(x: 288, y: 500), controlPoint1: NSPoint(x: 384, y: 230), controlPoint2: NSPoint(x: 300, y: 338))
shield.line(to: NSPoint(x: 260, y: 756))
shield.close()
NSColor.white.withAlphaComponent(0.96).setFill()
shield.fill()

let blue = NSColor(calibratedRed: 0.08, green: 0.43, blue: 0.82, alpha: 1)
let shackle = NSBezierPath()
shackle.move(to: NSPoint(x: 422, y: 548))
shackle.line(to: NSPoint(x: 422, y: 614))
shackle.curve(to: NSPoint(x: 602, y: 614), controlPoint1: NSPoint(x: 422, y: 704), controlPoint2: NSPoint(x: 602, y: 704))
shackle.line(to: NSPoint(x: 602, y: 548))
shackle.lineWidth = 48
shackle.lineCapStyle = .round
blue.setStroke()
shackle.stroke()

let lock = NSBezierPath(roundedRect: NSRect(x: 376, y: 340, width: 272, height: 222), xRadius: 36, yRadius: 36)
blue.setFill()
lock.fill()
NSColor.white.setFill()
NSBezierPath(ovalIn: NSRect(x: 488, y: 438, width: 48, height: 48)).fill()
let stem = NSBezierPath(roundedRect: NSRect(x: 499, y: 392, width: 26, height: 64), xRadius: 12, yRadius: 12)
stem.fill()

image.unlockFocus()
guard let tiff = image.tiffRepresentation,
      let bitmap = NSBitmapImageRep(data: tiff),
      let png = bitmap.representation(using: .png, properties: [:]) else {
    fatalError("Could not render icon")
}
try png.write(to: URL(fileURLWithPath: output))
