// Build the native icon from the same shield / rising evidence motif as favicon.svg.
import AppKit
let size = NSSize(width: 1024, height: 1024)
let image = NSImage(size: size)
image.lockFocus()
let scale: CGFloat = 8
let transform = NSAffineTransform()
transform.scale(by: scale)
transform.concat()
NSColor(calibratedRed: 21/255, green: 45/255, blue: 49/255, alpha: 1).setFill()
NSBezierPath(roundedRect: NSRect(x: 0, y: 0, width: 128, height: 128), xRadius: 28, yRadius: 28).fill()
let shield = NSBezierPath()
shield.move(to: NSPoint(x: 64, y: 110)); shield.line(to: NSPoint(x: 103, y: 94)); shield.line(to: NSPoint(x: 103, y: 65))
shield.curve(to: NSPoint(x: 64, y: 17), controlPoint1: NSPoint(x: 103, y: 40), controlPoint2: NSPoint(x: 85, y: 24))
shield.curve(to: NSPoint(x: 25, y: 65), controlPoint1: NSPoint(x: 43, y: 24), controlPoint2: NSPoint(x: 25, y: 40))
shield.line(to: NSPoint(x: 25, y: 94)); shield.close()
shield.lineWidth = 7; shield.lineJoinStyle = .round
NSColor(calibratedRed: 109/255, green: 218/255, blue: 194/255, alpha: 1).setStroke(); shield.stroke()
let arrow = NSBezierPath()
arrow.move(to: NSPoint(x: 43, y: 50)); arrow.line(to: NSPoint(x: 62, y: 69)); arrow.line(to: NSPoint(x: 75, y: 60)); arrow.line(to: NSPoint(x: 90, y: 83))
arrow.move(to: NSPoint(x: 74, y: 83)); arrow.line(to: NSPoint(x: 90, y: 83)); arrow.line(to: NSPoint(x: 90, y: 66))
arrow.lineWidth = 8; arrow.lineCapStyle = .round; arrow.lineJoinStyle = .round
NSColor.white.setStroke(); arrow.stroke()
image.unlockFocus()
let bitmap = NSBitmapImageRep(data: image.tiffRepresentation!)!
try bitmap.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
