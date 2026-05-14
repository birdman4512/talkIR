FROM fluent/fluent-bit:5.0

# Copy pipeline configuration
COPY fluent-bit.conf /fluent-bit/etc/fluent-bit.conf
COPY parsers.conf     /fluent-bit/etc/parsers.conf
COPY extract_index.lua /fluent-bit/scripts/extract_index.lua

CMD ["/fluent-bit/bin/fluent-bit", "-c", "/fluent-bit/etc/fluent-bit.conf"]
