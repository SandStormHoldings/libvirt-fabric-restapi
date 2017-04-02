<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="text"/>

  <xsl:template match="root">
    <xsl:apply-templates select="domain"/>
  </xsl:template>

  <xsl:template match="domain">
    <xsl:apply-templates select="devices"/>
  </xsl:template>

  <xsl:template match="devices">
    <xsl:apply-templates select="interface"/>
  </xsl:template>

  <xsl:template match="interface">
    <xsl:apply-templates select="mac"/>
  </xsl:template>

  <xsl:template match="mac">
    <xsl:for-each select="@address">
      <xsl:value-of select="."/>
      <xsl:text>&#10;</xsl:text>
    </xsl:for-each>
  </xsl:template>

</xsl:stylesheet>