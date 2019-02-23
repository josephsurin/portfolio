---
title: Generating hexagons with SVG
slug: generating-hexagons-with-svg
date: 22/02/2019
tags: development,react,project,frontend
---

## Overview

I recently wrote a [React button component set](https://josephsurin.github.io/tiled-hexagons) that renders SVG hexagons as buttons, with features such as perceived 3D effects and tessellation of multiple hexagon buttons.

When I was getting started with the project, I used Inkscape's built in polygon tool to create a hexagon and used that SVG for the hexagon shape. It didn't take me too long to realise that this wasn't a very good approach as I had troubles with the sizings of the hexagons and rounding their corners.

I decided to write my own [function](https://github.com/josephsurin/tiled-hexagons/blob/master/src/generateHexSVG.javascript) that generates the SVG commands that represents a hexagon with a certain shape and a certain amount of rounding as a string which I would then pass to the `d` attribute of a `<path>` element.

## Generating the SVG commands

The big picture goal of this function is to create a string that consists of SVG commands which draw out a hexagon with a given side length and border radius.

### The setup

Since we're dealing with a 2D coordinate system, it seems reasonable that we'd need a 2D vector structure to make things easier to handle. I wasn't interested in pulling in a package for something so trivial, so I wrote my own minimal `Vec2` class.
```javascript
class Vec2 {
	constructor(x, y) {
		this.x = x
		this.y = y
	}
	
	magnitude() {
		return Math.sqrt(this.x * this.x + this.y * this.y)
	}

	scalarMultiple(k) {
		return new Vec2(k * this.x, k * this.y)
	}

	normalize() {
		return this.scalarMultiple(1 / this.magnitude())
	}

	add(v2) {
		return new Vec2(this.x + v2.x, this.y + v2.y)
	}

	subtract(v2) {
		return this.add(v2.scalarMultiple(-1))
	}
}
```
In order to write the SVG commands, I decided it would be cleanest to have an `SVGCommands` class that has the SVG commands as instance methods as well as a `toString()` method which returns our desired commands string. I referred to the [MDN docs for SVG paths](https://developer.mozilla.org/en-US/docs/Web/SVG/Tutorial/Paths) to know which commands to implement.
```javascript
class SVGCommands {
	constructor() {
		this.commands = []
	}

	toString() {
		return this.commands.join(' ')
	}

	//svg move to command
	M(vec2) {
		this.commands.push(`M${vec2.x} ${vec2.y}`)
		return this
	}

	//svg draw line to point from current position command
	L(vec2) {
		this.commands.push(`L${vec2.x} ${vec2.y}`)
		return this
	}

	//svg bezier quadratic curve command
	Q(controlVec2, endVec2) {
		this.commands.push(`Q${controlVec2.x} ${controlVec2.y} ${endVec2.x} ${endVec2.y}`)
		return this
	}

	//svg shortcut close path command
	Z() {
		this.commands.push('Z')
		return this
	}
}
```
As you can see from the code, each of the `M`, `L`, `Q` and `Z` instance methods simply push a string onto the commands property of the object. I made each method return its instance just for convenience, so that dot chaining would be possible.

### Writing the function

I had already decided that the function's signature would looks something like `generateHexSVG(sideLength, borderRadius) => string of SVG commands`. Essentialy, the parameters I had to work with were the `sideLength` and the `borderRadius` parameters.
From the geometry of a hexagon, we can determine the width and height of it based on the given side length.
<img src="posts/assets/hexgeometry.png" width="200" align="right" />

The `width` of the hexagon is given by
$$w = 2 \times \frac{\sqrt3 s}{2} = \sqrt3 s$$
and the `height` is given by
$$h = 2 \times \frac{s}{2} + s = 2 s$$

The next step is to find a position vector for each vertex of the hexagon; if we know where each vertex is, we can move to one of them and draw lines to its neighbours to form the hexagon shape.

For convenience, we'll name each vertex with a letter, starting with the top vertex being `a`, the one to its immediate right being `b`, and the one immediately left of `a` being `f`.

<img src="posts/assets/hexlabelled.png" width="200" align="right"/>

Looking at these two images, it isn't hard to determine the position vectors for each of the vertices. With the origin being at the top left as per SVG standards, the positions of the vertices are:

$$\begin{aligned} a &= (\frac{w}{2}, 0) \hspace{0.3in} b = (w, \frac{h}{4}) \cr c &= (w, \frac{3h}{4}) \hspace{0.2in} d = (\frac{w}{2}, h) \cr e &= (0, \frac{3h}{4}) \hspace{0.2in} f = (0, \frac{h}{4})  \end{aligned}$$

This is easy enough to translate into Javascript:
```javascript
//from geometry of a hexagon
var width = Math.sqrt(3) * sideLength
var height = 2 * sideLength

//a, b, c, d, e and f represent the vertices
var a, b, c, d, e, f
//start at the top point
a = new Vec2(width / 2, 0)
b = new Vec2(width, height / 4)
c = new Vec2(width, 3 * height / 4)
d = new Vec2(width / 2, height)
e = new Vec2(0, 3 * height / 4)
f = new Vec2(0, height / 4)
```

Now, if the hexagon is sharp and has a border radius of 0, then all we need to do is move to a point and draw lines to each edge in a cyclic manner. To avoid inefficiency, we first check if the `borderRadius` is `0` and return the pointy hexagon if it is:
```javascript
if(borderRadius == 0) {
  var pointyHexagon = new SVGCommands()
  return pointyHexagon.M(a).L(b).L(c).L(d).L(e).L(f).Z().toString()
}
```

#### Rounded corners

If instead the hexagon is to have smooth corners, we'll need a way to make the corners rounded. Bezier curves are the right tool for this type of job, and for this particlar case, a quadratic curve will be most suitable. SVG allows us to create a quadratic curve by passing 4 parameters to the `Q` command. The parameters are `x1 y1 x y` where `x1` and `y1` are the coordinates of the control point and `x` and `y` are the coordinates of the end point.
<img src="https://mdn.mozillademos.org/files/10403/Quadratic_Bezier_with_grid.png" align="right" />
The image to the right [from MDN docs](https://developer.mozilla.org/en-US/docs/Web/SVG/Tutorial/Paths) shows this behaviour. The three red points are our points of interest and the black curve is the resulting quadratic curve. The point on the far left is the current position, i.e. the point that we arrive at after using an `M` or `L` command. The point in the middle is the control point, and the point on the far right is the end point. The line passing through the current point and the control point is tangent to the curve, this is also true for the line passing through the end point and the control point. Hence, if we let the control point be the vertex of a hexagon, and the start and end points to be some points along the hexagon's perimeter, by using the quadratic curve command, we can emulate rounded corners. 
<img src="posts/assets/hexdv.png" width="200" align="right" />

To help us with this, we'll define some new vectors $\overrightarrow{dl}$, $\overrightarrow{dr}$ and $\overrightarrow{dd}$ which are vectors parallel to the sides of the hexagon and with magnitude equal to `borderRadius`. Specifically:

$$\begin{aligned} \overrightarrow{dl} &= br \times unit(f-a) \cr \overrightarrow{dr} &= br \times unit(b-a) \cr \overrightarrow{dd} &= br \times unit(e-f) \end{aligned}$$

where $br$ is the border radius. Translating this to code:

```javascript
var dl = f.subtract(a).normalize().scalarMultiple(borderRadius)
var dr = b.subtract(a).normalize().scalarMultiple(borderRadius)
var dd = new Vec2(0, borderRadius)
```

To show how we can achieve rounded corners for the hexagon, I'll just show the process for one corner, from which the others will follow logically. We'll start with corner `a`. The point `a` itself will be the control point, the point that is `borderRadius` units to the left of `a` along `af` will be the start point and the point that is `borderRadius` units to the right of `a` along `ab` will be the end point. Thus, we begin by moving to the start point using the `M` command, then, by using the `Q` command with the control point and end point as parameters, we will have generated the path for the rounded corner. Since the `Q` command moves us to a point slightly to the right of `a`, we need to draw a line to the start point of our next corner `b`. The process to round `b` is similar to the process to round `a` except since we are already at the start point, we don't need another `M` command.
```javascript
var roundedHexagon = new SVGCommands()
  .M(a.add(dl))
  .Q(a, a.add(dr))
  .L(b.subtract(dr))
```

### Bringing it all together

Our final function to generate a hexagon SVG path from its side length and border radius would then look something like this (with the `Vec2` and `SVGCommands` classes defined as above):

```javascript
function generateHexSVG(sideLength, borderRadius) {
	var width = Math.sqrt(3) * sideLength
	var height = 2 * sideLength

	var a, b, c, d, e, f
	a = new Vec2(width / 2, 0)
	b = new Vec2(width, height / 4)
	c = new Vec2(width, 3 * height / 4)
	d = new Vec2(width / 2, height)
	e = new Vec2(0, 3 * height / 4)
	f = new Vec2(0, height / 4)

	if(borderRadius == 0) {
		var pointyHexagon = new SVGCommands()
		return pointyHexagon.M(a).L(b).L(c).L(d).L(e).L(f).Z().toString()
	}

	var dl = f.subtract(a).normalize().scalarMultiple(borderRadius)
	var dr = b.subtract(a).normalize().scalarMultiple(borderRadius)
	var dd = new Vec2(0, borderRadius)

	var roundedHexagon = new SVGCommands()
	roundedHexagon
		.M(a.add(dl))
		.Q(a, a.add(dr))
		.L(b.subtract(dr))
		.Q(b, b.add(dd))
		.L(c.subtract(dd))
		.Q(c, c.add(dl))
		.L(d.subtract(dl))
		.Q(d, d.subtract(dr))
		.L(e.add(dr))
		.Q(e, e.subtract(dd))
		.L(f.add(dd))
		.Q(f, f.subtract(dl))
		.Z()

	return roundedHexagon.toString()
}
```

Checkout the project's [live demo](https://josephsurin.github.io/tiled-hexagons/) and [source code](https://github.com/josephsurin/tiled-hexagons)!
