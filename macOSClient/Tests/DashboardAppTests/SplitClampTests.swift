import AppKit
import EvidenceCore
import XCTest
@testable import ReinsDashboardApp

/// A flipped container stands in for the SwiftUI hosting view: y = 0 is the top,
/// so a document-height child extends past the window and the visible slice is its top.
private final class FlippedContainer: NSView {
    override var isFlipped: Bool { true }
}

@MainActor
final class SplitClampTests: XCTestCase {
    func testDocumentHeightSplitIsShrunkAndHeadingLandsInsideTheContentRect() {
        let window = makeWindow()
        defer { window.close() }
        let content = window.contentView!
        let flipped = FlippedContainer(frame: content.bounds)
        content.addSubview(flipped)
        let host = NSView(frame: NSRect(x: 0, y: 0, width: flipped.bounds.width, height: 11_488))
        flipped.addSubview(host)
        let split = NSSplitView(frame: NSRect(x: 0, y: 0, width: host.bounds.width, height: 5_089))
        split.isVertical = true
        host.addSubview(split)

        let sidebar = NSView(frame: NSRect(x: 0, y: 0, width: 218, height: 5_089))
        let heading = NSTextField(labelWithString: "All evidence")
        heading.frame = NSRect(x: 12, y: 5_049, width: 180, height: 22)
        heading.setAccessibilityLabel("All evidence")
        sidebar.addSubview(heading)
        let bottom = NSTextField(labelWithString: "bottom marker")
        bottom.frame = NSRect(x: 12, y: 8, width: 160, height: 18)
        sidebar.addSubview(bottom)
        split.addSubview(sidebar)
        split.addSubview(NSView(frame: NSRect(x: 219, y: 0, width: 680, height: 1_469.5)))
        split.addSubview(NSView(frame: NSRect(x: 900, y: 0, width: 300, height: 11_488)))

        XCTAssertTrue(window.canBecomeMain)
        XCTAssertEqual(host.frame.height, 11_488, accuracy: 0.1)
        XCTAssertEqual(split.frame.height, 5_089, accuracy: 0.1)
        let proposed = NSRect(x: 0, y: 0, width: split.frame.width, height: 11_488)
        let capped = SplitFrameCap.capped(proposed, view: split)
        let layout = window.contentLayoutRect
        XCTAssertGreaterThan(layout.height, 2)
        XCTAssertLessThan(layout.height, window.frame.height)
        XCTAssertLessThanOrEqual(capped.height, layout.height + 1)
        XCTAssertGreaterThan(capped.height, 2)
        XCTAssertNotEqual(capped.height, 11_488, accuracy: 0.1)
        let limit = SplitFrameCap.visibleLimit(in: host, window: window)
        XCTAssertGreaterThanOrEqual(capped.minY, limit.minY - 1)
        XCTAssertLessThanOrEqual(capped.maxY, limit.maxY + 1)
        XCTAssertGreaterThanOrEqual(capped.minX, limit.minX - 1)
        XCTAssertLessThanOrEqual(capped.maxX, limit.maxX + 1)

        DashboardAppDelegate.clampLiveSplits()
        content.layoutSubtreeIfNeeded()

        XCTAssertLessThanOrEqual(host.frame.height, layout.height + 1)
        XCTAssertLessThan(host.frame.height, 11_488)
        XCTAssertLessThanOrEqual(split.frame.height, layout.height + 1)
        XCTAssertLessThan(split.frame.height, 5_089)
        XCTAssertGreaterThan(split.frame.height, 2)
        if abs(layout.height - WindowPlacement.minimum.height) > 1 {
            XCTAssertNotEqual(split.frame.height, WindowPlacement.minimum.height)
        }
        XCTAssertTrue(DashboardAppDelegate.splitViewsFit(window))

        let splitInWindow = split.convert(split.bounds, to: nil)
        XCTAssertGreaterThanOrEqual(splitInWindow.minY, layout.minY - 1)
        XCTAssertLessThanOrEqual(splitInWindow.maxY, layout.maxY + 1)
        XCTAssertGreaterThanOrEqual(splitInWindow.minX, layout.minX - 1)
        XCTAssertLessThanOrEqual(splitInWindow.maxX, layout.maxX + 1)
        let hostInWindow = host.convert(host.bounds, to: nil)
        XCTAssertGreaterThanOrEqual(hostInWindow.minY, layout.minY - 1)
        XCTAssertLessThanOrEqual(hostInWindow.maxY, layout.maxY + 1)

        let panes = split.arrangedSubviews
        XCTAssertGreaterThanOrEqual(panes.count, 3)
        XCTAssertEqual(panes[0].frame.height, split.bounds.height, accuracy: 1.5)
        XCTAssertEqual(panes[0].frame.minY, split.bounds.minY, accuracy: 1.5)
        XCTAssertGreaterThanOrEqual(panes[0].frame.width, 140)
        XCTAssertLessThan(panes[0].frame.width, split.bounds.width * 0.5)
        XCTAssertNotEqual(panes[0].frame.width, 5_089, accuracy: 1)
        XCTAssertEqual(panes[1].frame.height, split.bounds.height, accuracy: 1.5)
        XCTAssertNotEqual(panes[1].frame.height, 1_469.5, accuracy: 0.1)
        XCTAssertGreaterThanOrEqual(panes[2].frame.width, 200)
        XCTAssertLessThan(panes[2].frame.height, 11_488)

        let screenContent = window.convertToScreen(layout)
        let headingFrame = heading.accessibilityFrame()
        XCTAssertGreaterThan(headingFrame.width, 1)
        XCTAssertGreaterThan(headingFrame.height, 1)
        XCTAssertTrue(contains(screenContent, headingFrame), "heading \(headingFrame) content \(screenContent)")
        let bottomFrame = bottom.convert(bottom.bounds, to: nil)
        let bottomScreen = bottom.window?.convertToScreen(bottomFrame) ?? .zero
        XCTAssertGreaterThan(bottomScreen.height, 1)
        XCTAssertFalse(contains(screenContent, bottomScreen), "bottom marker stayed on screen \(bottomScreen)")
    }

    func testHorizontalSplitFillsWidthWithoutForcingPaneHeight() {
        let window = makeWindow()
        defer { window.close() }
        let content = window.contentView!
        let split = NSSplitView(frame: NSRect(x: 0, y: 0, width: 400, height: 9_000))
        split.isVertical = false
        content.addSubview(split)
        let upper = NSView(frame: NSRect(x: 0, y: 200, width: 80, height: 120))
        let lower = NSView(frame: NSRect(x: 0, y: 0, width: 80, height: 80))
        split.addSubview(upper)
        split.addSubview(lower)

        DashboardAppDelegate.clampLiveSplits()

        let layout = window.contentLayoutRect
        XCTAssertLessThanOrEqual(split.frame.height, layout.height + 1)
        XCTAssertGreaterThan(split.frame.height, 200)
        XCTAssertEqual(upper.frame.width, split.bounds.width, accuracy: 1)
        XCTAssertEqual(lower.frame.width, split.bounds.width, accuracy: 1)
        XCTAssertEqual(upper.frame.height, 120, accuracy: 1)
        XCTAssertEqual(lower.frame.height, 80, accuracy: 1)
        XCTAssertNotEqual(upper.frame.height, split.bounds.height)
        XCTAssertNotEqual(lower.frame.height, split.bounds.height)
        let upperInWindow = split.convert(upper.frame, to: nil)
        XCTAssertGreaterThanOrEqual(upperInWindow.minY, layout.minY - 1)
        XCTAssertLessThanOrEqual(upperInWindow.maxY, layout.maxY + 1)
    }

    private func makeWindow() -> NSWindow {
        let window = NSWindow(
            contentRect: NSRect(x: 216, y: 54, width: 1_224, height: 816),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false)
        window.title = "ReinsCredential"
        window.setFrame(NSRect(x: 216, y: 54, width: 1_224, height: 816), display: true)
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
        window.layoutIfNeeded()
        return window
    }

    private func contains(_ content: NSRect, _ frame: NSRect) -> Bool {
        guard frame.width > 1, frame.height > 1, frame.height <= content.height + 2 else { return false }
        return frame.minY >= content.minY - 1 && frame.maxY <= content.maxY + 1
            && frame.minX >= content.minX - 1 && frame.maxX <= content.maxX + 1
    }
}
