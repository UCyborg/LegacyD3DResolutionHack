# Legacy Direct3D Resolution Hack

Simple proxy DLL which removes artificial limitation from legacy Direct3D 7 and below,
allowing older Direct3D applications and games to run at resolution which width/height
exceeds 2048 pixels.

The application must be able to pick the desired resolution on its own, this
doesn't add new resolutions to applications with hardcoded resolution list, it merely
prevents Direct3D device creation function from returning an error when passed DirectDraw
surface with width/height exceeding 2048 pixels.

The current implementation doesn't work with all games, need to make ddraw.dll based proxy.
